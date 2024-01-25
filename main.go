package main

import (
    "fmt"
    "os"
    "flag"
    "embed"
    "errors"

    "html/template"
    "net/http"
    "encoding/json"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    // Configuration
    "github.com/peterbourgon/ff/v3"
)

type secret struct {
    Secret       string `json:"secret"`
    Views        int    `json:"views"`
    ClickThrough bool   `json:"click"`
}

// This variable is overwritten at compile/link time using -ldflags
var version = "development-build"

var secretStore = make(map[uuid.UUID]secret)

//go:embed templates/*
var embeddedTemplates embed.FS

var viewPage *template.Template
var clickthroughPage *template.Template

func main() {
    fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
    var versionFlagPtr = fs.Bool("version", false, "Print the version information and exit")
    var listenAddrPtr  = fs.String("listen", "localhost:8080", "The address and port for the webserver to listen on")

    // Ingest configuration flags.
    // Commandline arguments > Environment variables > config file
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

    router := chi.NewRouter()
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("SecretLinks"))
    })
    router.Route("/api", func(apiRouter chi.Router) {
        apiRouter.Post("/secret", newSecret)
    })
    router.Get("/secret/{id}", getSecret)
    router.Post("/secret/{id}", clickthroughRetrieveSecret)

    if err := http.ListenAndServe(*listenAddrPtr, router); err != nil {
        fmt.Printf("could not start webserver: %v\n", err)
        os.Exit(1)
    }
}

func getSecret(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    secretID, err := uuid.Parse(id)
    if err != nil {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    retrievedSecret, ok := secretStore[secretID]
    if ok && retrievedSecret.Views > 0 {
        if !retrievedSecret.ClickThrough {
            // Clickthrough not enabled, show secret immediately
            retrievedSecret.Views--
            secretStore[secretID] = retrievedSecret
            viewPage.Execute(w, retrievedSecret)
        } else {
            // Clickthrough enabled, return page with button to retrieve (additional request)
            data := struct {
                SecretID string
            } {
                SecretID: id,
            }
            clickthroughPage.Execute(w, data)
        }
    } else {
        http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
        return
    }
}

func clickthroughRetrieveSecret(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    secretID, err := uuid.Parse(id)
    if err != nil {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    retrievedSecret, ok := secretStore[secretID]
    if ok && retrievedSecret.Views > 0 {
        retrievedSecret.Views--
        secretStore[secretID] = retrievedSecret
        viewPage.Execute(w, retrievedSecret)
    }
}

func newSecret(w http.ResponseWriter, r *http.Request) {
    payload := &secret{}
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
    secretStore[id] = *payload

    w.Write([]byte(fmt.Sprintf("%v", id)))
}

