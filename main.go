package main

import (
    "fmt"
    "os"
    "flag"
    "time"
    "embed"
    "errors"

    "html/template"
    "net/http"
    "encoding/json"
    "encoding/base64"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    // Configuration
    "github.com/peterbourgon/ff/v3"

    bolt "go.etcd.io/bbolt"

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
        fmt.Printf("error decrypting: %v\n", err)
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

    viewPage = template.Must(template.ParseFS(embeddedTemplates, "templates/view.html"))
    clickthroughPage = template.Must(template.ParseFS(embeddedTemplates, "templates/reveal.html"))

    // DB setup
    db, err = bolt.Open(*dbfilePtr, 0600, &bolt.Options{Timeout: 10 * time.Second})
    if err != nil {
        fmt.Println(err)
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

    router := chi.NewRouter()
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("SecretLinks"))
    })
    router.Route("/api", func(apiRouter chi.Router) {
        apiRouter.Post("/secret", newSecret)
    })
    router.Get("/secret/{id}/{key}", getSecret)
    router.Post("/secret/{id}/{key}", clickthroughRetrieveSecret)

    if err := http.ListenAndServe(*listenAddrPtr, router); err != nil {
        fmt.Printf("could not start webserver: %v\n", err)
        os.Exit(1)
    }
}

func getSecret(w http.ResponseWriter, r *http.Request) {
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

        if !retrievedSecret.ClickThrough {
            // Clickthrough not enabled, show secret immediately
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

func clickthroughRetrieveSecret(w http.ResponseWriter, r *http.Request) {
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
        fmt.Printf("error storing secret in DB: %v\n", err)
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
        fmt.Printf("error getting secret from DB: %v\n", err)
    }
    return retrievedSecret, nil
}

func storeSecretInDatabase(key uuid.UUID, value storedSecret, updateIfExists bool) error {
    jsonData, err := json.Marshal(value)
    if err != nil {
        fmt.Println(err)
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
