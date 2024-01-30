package main

import (
    "fmt"
    "os"
    "flag"
    "time"
    "embed"
    "errors"
    "log/slog"

    "html/template"
    "net/http"
    "encoding/json"
    "encoding/base64"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/httplog/v2"
    "github.com/google/uuid"

    // Configuration
    "github.com/peterbourgon/ff/v3"

    bolt "go.etcd.io/bbolt"

    "secretlinks/logging"
    "secretlinks/cryptopasta"
)

// API payload of incoming request (create new secret)
type payloadSecret struct {
    Secret       string `json:"secret"`
    Views        int    `json:"views"`
    ClickThrough bool   `json:"click"`
}

// Data stored in persistent storage (secret encrypted)
type storedSecret struct {
    Secret       []byte `json:"secret"`
    Views        int    `json:"views"`
    ClickThrough bool   `json:"click"`
    CreationDate string `json:"created"`
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

var viewPage *template.Template
var clickthroughPage *template.Template

func main() {
    fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
    var versionFlagPtr = fs.Bool("version", false, "Print the version information and exit")
    var listenAddrPtr  = fs.String("listen", "localhost:8080", "The address and port for the webserver to listen on")
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

    viewPage = template.Must(template.ParseFS(embeddedTemplates, "templates/view.html"))
    clickthroughPage = template.Must(template.ParseFS(embeddedTemplates, "templates/reveal.html"))

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

            viewPage.Execute(w, struct{
                Secret string
                Views int
            } {
                Secret: decryptedSecret,
                Views: retrievedSecret.Views,
            })
        } else {
            // Clickthrough enabled, return page with button to retrieve (additional request)
            clickthroughPage.Execute(w, nil)
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
        ClickThrough: payload.ClickThrough,
        CreationDate: time.Now().UTC().Format(time.RFC3339),
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
        err := b.Delete(key[:])
        return err
    })
    return err
}
