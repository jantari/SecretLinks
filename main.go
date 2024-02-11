package main

import (
    "fmt"
    "os"
    "io/fs"
    "flag"
    "time"
    "embed"
    "errors"
    "strings"
    "log/slog"
    "path/filepath"

    "html/template"
    "net/http"
    "encoding/json"
    "encoding/base64"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/httplog/v2"
    "github.com/google/uuid"

    // Configuration
    "github.com/peterbourgon/ff/v3"

    // Persistent secret storage
    bolt "go.etcd.io/bbolt"

    "secretlinks/logging"
    "secretlinks/cryptopasta"

    // Localization of the little UI we have
    "golang.org/x/text/language"
    "golang.org/x/text/message"
    "golang.org/x/text/message/catalog"
)

// API payload of incoming request (create new secret)
type payloadSecret struct {
    Secret       string `json:"secret"`
    Views        int    `json:"views"`
    ExpireDays   int    `json:"expires"`
    ClickThrough bool   `json:"click"`
}

// Data stored in persistent storage (secret encrypted)
type storedSecret struct {
    Secret       []byte    `json:"secret"`
    Views        int       `json:"views"`
    ExpireDays   int       `json:"expires"`
    ClickThrough bool      `json:"click"`
    CreationDate time.Time `json:"created"`
}

func (s storedSecret) decryptSecret(key [32]byte) (string, error) {
    plaintext, err := cryptopasta.Decrypt(s.Secret, &key)
    if err != nil {
        logging.Logger.Error("could not decrypt secret", slog.Any("error", err))
        return "", err
    }

    return string(plaintext), nil
}

// This variable is overwritten at compile/link time using -ldflags
var version = "development-build"

var db *bolt.DB

//go:embed templates/*
var embeddedTemplates embed.FS

var localizedViewPage map[language.Tag]*template.Template
var localizedClickPage map[language.Tag]*template.Template

// Make sure the undefined ('und') language is the first in the list,
// so that NewMatcher uses it as its fallback option.
var serverLangs = []language.Tag{
    language.Und,
}
var translationCatalog catalog.Catalog

func main() {
    fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
    var versionFlagPtr = fs.Bool("version", false, "Print the version information and exit")
    var listenAddrPtr  = fs.String("listen", "localhost:8080", "The address and port for the webserver to listen on")
    var translationPtr = fs.String("translationPath", "./translations", "Directory with optional JSON translation files")
    var logLevelPtr    = fs.String("logLevel", "info", "Set log verbosity: error, warn, info or debug")
    var dbfilePtr      = fs.String("dbfile", "./store.db", "Path to the Bolt database file to store secrets")

    // Ingest configuration flags.
    // Commandline arguments > Environment variables
    err := ff.Parse(
        fs,
        os.Args[1:],
        ff.WithEnvVarPrefix("SECRETLINKS"),
    )
    if err != nil {
        // Replicate default ExitOnError behavior of exiting with 0 when -h/-help/--help is used
        if errors.Is(err, flag.ErrHelp) {
            os.Exit(0)
        }
        fmt.Println(err)
        os.Exit(2)
    }

    if *versionFlagPtr {
        fmt.Printf("SecretLinks %v\nhttps://github.com/jantari/SecretLinks\n", version)
        os.Exit(0)
    }

    fmt.Printf("SecretLinks %v\n", version)

    logging.InitLogging(*logLevelPtr)

    expiredSecrets := make(chan []byte)
    go backgroundScan(expiredSecrets)
    go backgroundPrune(expiredSecrets)

    var additionalServerLangs []language.Tag
    additionalServerLangs, translationCatalog = loadTranslations(*translationPtr)
    serverLangs = append(serverLangs, additionalServerLangs...)

    // Prepare localized page templates for every supported language
    localizedViewPage = map[language.Tag]*template.Template{}
    for _, lang := range serverLangs {
        localizedViewPage[lang] = template.Must(template.New("view.html").Funcs(template.FuncMap{
            "translate": translatePageSnippet(lang),
        }).ParseFS(embeddedTemplates, "templates/view.html"))
    }

    localizedClickPage = map[language.Tag]*template.Template{}
    for _, lang := range serverLangs {
        localizedClickPage[lang] = template.Must(template.New("reveal.html").Funcs(template.FuncMap{
            "translate": translatePageSnippet(lang),
        }).ParseFS(embeddedTemplates, "templates/reveal.html"))
    }

    // DB setup
    db, err = bolt.Open(*dbfilePtr, 0600, &bolt.Options{Timeout: 10 * time.Second})
    if err != nil {
        logging.Logger.Error("could not open database", slog.Any("error", err))
        os.Exit(1)
    }
    defer db.Close()

    err = db.Update(func(tx *bolt.Tx) error {
        _, err = tx.CreateBucketIfNotExists([]byte("Secrets"))
        if err != nil {
            return fmt.Errorf("error creating bucket: %s", err)
        }
        return nil
    })
    if err != nil {
        logging.Logger.Error("could not initialize database", slog.Any("error", err))
        os.Exit(1)
    }

    router := chi.NewRouter()
    router.Use(httplog.RequestLogger(logging.HttpLogger))
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("SecretLinks"))
    })
    router.Route("/api", func(apiRouter chi.Router) {
        apiRouter.Post("/secret", newSecret)
    })
    router.HandleFunc("/secret/{id}/{key}", viewPageHandler)

    if err := http.ListenAndServe(*listenAddrPtr, router); err != nil {
        logging.Logger.Error("could not start webserver", slog.Any("error", err))
        os.Exit(1)
    }
}

func viewPageHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet && r.Method != http.MethodPost {
        http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
        return
    }

    accept := r.Header.Get("Accept-Language")
    // NewMatcher returns the first element in the list in case no match is found,
    // so we want to make sure the first element is the undefiend language as that's
    // set up to handle all fallback scenarios.
    matcher := language.NewMatcher(serverLangs)
    tag, _ := language.MatchStrings(matcher, accept)
    logging.Logger.Debug("request language preference", slog.String("header", accept), slog.Any("decision", tag))

    id := chi.URLParam(r, "id")
    key := chi.URLParam(r, "key")
    keyBytes, err := base64.URLEncoding.DecodeString(key)
    if err != nil || len(keyBytes) != 32 {
        // invalid decryption key
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    secretID, err := uuid.Parse(id)
    if err != nil {
        // invalid UUID
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    retrievedSecret, err := getSecretFromDatabase(secretID)

    if err == nil && retrievedSecret.Views > 0 {
        decryptedSecret, err := retrievedSecret.decryptSecret([32]byte(keyBytes))
        if err != nil {
            // Return 404 on decryption failures to not give away the requester
            // found a valid GUID in case they are just guessing URLs.
            // TODO: mitigate timing attacks
            http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
            return
        }

        // Fallback in case nothing matches
        var localizedTemplateToRender *template.Template

        // When clickthrough is not enabled or request is POST, show secret immediately.
        // A POST request is triggered by the "reveal" button on the clickthrough page.
        if !retrievedSecret.ClickThrough || r.Method == http.MethodPost {
            retrievedSecret.Views--
            if retrievedSecret.Views < 1 {
                err = deleteSecretFromDatabase(secretID)
            } else {
                err = storeSecretInDatabase(secretID, retrievedSecret, true)
            }
            if err != nil {
                http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
                return
            }

            // Finding a best-match betweeen two language.Tag. This is how go itself does it:
            // https://cs.opensource.google/go/x/text/+/refs/tags/v0.14.0:message/catalog/catalog.go;l=231
            for ; ; tag = tag.Parent() {
                var ok bool
                localizedTemplateToRender, ok = localizedViewPage[tag]
                if ok || tag == language.Und {
                    break
                }
            }

            err = localizedTemplateToRender.Execute(w, struct{
                Secret string
                Views int
            } {
                Secret: decryptedSecret,
                Views: retrievedSecret.Views,
            })
            if err != nil {
                logging.Logger.Error("could not template response", slog.Any("error", err))
            }
        } else {
            // Clickthrough enabled, return page with button to retrieve (additional request)

            // Finding a best-match betweeen two language.Tag. This is how go itself does it:
            // https://cs.opensource.google/go/x/text/+/refs/tags/v0.14.0:message/catalog/catalog.go;l=231
            for ; ; tag = tag.Parent() {
                var ok bool
                localizedTemplateToRender, ok = localizedClickPage[tag]
                if ok || tag == language.Und {
                    break
                }
            }

            err = localizedTemplateToRender.Execute(w, nil)
            if err != nil {
                logging.Logger.Error("could not template response", slog.Any("error", err))
            }
        }
    } else {
        http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
        return
    }
}

func newSecret(w http.ResponseWriter, r *http.Request) {
    payload := &payloadSecret{}
    d := json.NewDecoder(r.Body)
    d.DisallowUnknownFields() // catch unwanted fields

    err := d.Decode(&payload)
    if err != nil {
        // bad JSON or unrecognized json field
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    id := uuid.New()
    if payload.Views < 1 {
        payload.Views = 1
    }
    if payload.ExpireDays < 1 {
        payload.ExpireDays = 3
    }

    key := cryptopasta.NewEncryptionKey()
    secretBytes := []byte(payload.Secret)
    encryptedSecret, err := cryptopasta.Encrypt(secretBytes, key)
    if err != nil {
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    data := storedSecret{
        Secret: encryptedSecret,
        Views: payload.Views,
        ExpireDays: payload.ExpireDays,
        ClickThrough: payload.ClickThrough,
        CreationDate: time.Now().UTC(),
    }
    err = storeSecretInDatabase(id, data, false)
    if err != nil {
        logging.Logger.Error("could not store secret in DB", slog.Any("error", err))
        http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
        return
    }

    w.Write([]byte(fmt.Sprintf("secret/%v/%v\n", id, base64.URLEncoding.EncodeToString(key[:]))))
}

func getSecretFromDatabase(key uuid.UUID) (storedSecret, error) {
    var retrievedSecret storedSecret
    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        v := b.Get(key[:])
        if v == nil {
            return nil
        }
        err := json.Unmarshal(v, &retrievedSecret)
        if err != nil {
            return err
        }
        return nil
    })
    if err != nil {
        logging.Logger.Error("could not get secret from DB", slog.Any("error", err))
    }
    return retrievedSecret, nil
}

func storeSecretInDatabase(key uuid.UUID, value storedSecret, updateIfExists bool) error {
    jsonData, err := json.Marshal(value)
    if err != nil {
        logging.Logger.Error("could not marshal secret", slog.Any("error", err))
        return err
    }

    err = db.Update(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        // Abort if the key already exists and update isn't set
        if !updateIfExists && b.Get(key[:]) != nil {
            return errors.New("key aready exists")
        }
        err := b.Put(key[:], []byte(jsonData))
        return err
    })

    return err
}

func deleteSecretFromDatabase(key uuid.UUID) error {
    err := db.Update(func (tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        return b.Delete(key[:])
    })
    return err
}

func backgroundScan(channel chan []byte) {
    // Every 10 minutes, open the database for reading and search for expired secrets
    for range time.NewTicker(10 * time.Minute).C {
        now := time.Now().UTC()
        // We can ignore the returne value because this closure never returns an error because
        // we don't want to break the loop and stop processing secrets just because one failed.
        _ = db.View(func(tx *bolt.Tx) error {
            b := tx.Bucket([]byte("Secrets"))
            c := b.Cursor()
            logging.Logger.Debug("checking for expired secrets", slog.Int("secretsCount", b.Stats().KeyN))

            for k, v := c.First(); k != nil; k, v = c.Next() {
                um := &storedSecret{}
                err := json.Unmarshal(v, &um)
                if err == nil {
                    if um.CreationDate.AddDate(0, 0, um.ExpireDays).Before(now) {
                        // Queue the secret to be deleted
                        channel <- k
                    }
                } else {
                    logging.Logger.Error("error unmarshaling secret", slog.String("secret", uuid.UUID(k).String()), slog.Any("error", err))
                }
            }
            return nil
        })
    }
}

func backgroundPrune(channel chan []byte) {
    // Whenever a key is pushed to this channel, lock the database for rw and delete the secret
    for v := range channel {
        secretUUID := uuid.UUID(v)
        err := deleteSecretFromDatabase(secretUUID)
        if err != nil {
            logging.Logger.Error("could not delete expired secret", slog.String("secret", secretUUID.String()), slog.Any("error", err))
        } else {
            logging.Logger.Info("deleted expired secret", slog.String("secret", secretUUID.String()))
        }
    }
}

// Implements catalog.Dictionary{} interface
type myOwnDictionary struct {
  Data map[string]string
}
func (d *myOwnDictionary) Lookup(key string) (data string, ok bool) {
  if value, ok := d.Data[key]; ok {
    return "\x02" + value, true
  }
  return "", false
}

func translatePageSnippet(tag language.Tag) func(msg string, a ...interface{}) string {
    return func(msg string, a ...interface{}) string {
        return message.NewPrinter(tag, message.Catalog(translationCatalog)).Sprintf(msg, a...)
    }
}

func loadTranslations(translationsPath string) ([]language.Tag, catalog.Catalog) {
    languages := []language.Tag{}
    translations := map[string]catalog.Dictionary{}
    // These hardcoded translations are assigned to the und / undefined language
    // because the 'und' language is the parent of all language Tags, at the root of the tree.
    // When a Dictionary has a language but cannot find a specific key-value translation, it will
    // look up the key in all the parent languages (aka if a key is missing/not found in it).
    // this means by defining translations for the 'und' language these failing lookups will
    // all eventually fallback to this.
    // For languages that aren't in the dictionary to begin with, we can explicitly specify
    // a fallback language, but to cover both cases we just set that to the 'und' language as well.
    translations["und"] = &myOwnDictionary{
        Data: map[string]string{
            "msg_reveal": "Reveal",
            "msg_copy": "COPY",
            "msg_views_remaining": "%d more views left.",
       },
    }

    files, err := os.ReadDir(translationsPath)
    if err != nil && !errors.Is(err, fs.ErrNotExist) {
        logging.Logger.Warn("could not read (all) translation files", slog.Any("error", err))
    }

    for _, file := range files {
        if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
            fileNameWithoutExtension := strings.TrimSuffix(file.Name(), ".json")
            translationLanguage, err := language.Parse(fileNameWithoutExtension)
            if err != nil {
                logging.Logger.Error("filename is not a recognized language tag", slog.String("file", file.Name()), slog.Any("error", err))
                continue
            }

            fileFullPath := filepath.Join(translationsPath, file.Name())
            translationFile, err := os.ReadFile(fileFullPath)
            if err != nil {
                logging.Logger.Error("file could not be read", slog.String("file", file.Name()), slog.Any("error", err))
                continue
            }

            translation := map[string]string{}
            err = json.Unmarshal(translationFile, &translation)
            if err != nil {
                logging.Logger.Error("file content could not be parsed", slog.String("file", file.Name()), slog.Any("error", err))
                continue
            }

            languages = append(languages, translationLanguage)
            translations[fileNameWithoutExtension] = &myOwnDictionary{
                Data: translation,
            }

            logging.Logger.Debug("translation loaded", slog.String("file", file.Name()), slog.Any("language", translationLanguage))
        }
    }

    c, err := catalog.NewFromMap(
        translations,
        catalog.Fallback(language.Und), // Und/Undefined is the default fallback but we'll be explicit
    )
    if err != nil {
        logging.Logger.Error("error creating translation catalog", slog.Any("error", err))
        os.Exit(1)
    }

    return languages, c
}

