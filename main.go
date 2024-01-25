package main

import (
    "fmt"

    "html/template"
    "net/http"
    "encoding/json"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type secret struct {
    Secret       string `json:"secret"`
    Views        int    `json:"views"`
    ClickThrough bool   `json:"click"`
}

// This variable is overwritten at compile/link time using -ldflags
var version = "development-build"

var secretStore = make(map[uuid.UUID]secret)

var tmpl = template.Must(template.ParseFiles("view.html"))
var clickthroughPage = template.Must(template.ParseFiles("reveal.html"))

func main() {
    fmt.Printf("SecretLinks %v\n", version)

    router := chi.NewRouter()
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("SecretLinks"))
    })
    router.Route("/api", func(apiRouter chi.Router) {
        apiRouter.Post("/secret", newSecret)
    })
    router.Get("/secret/{id}", getSecret)
    router.Post("/secret/{id}", clickthroughRetrieveSecret)

    http.ListenAndServe(":8080", router)
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
            tmpl.Execute(w, retrievedSecret)
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
        tmpl.Execute(w, retrievedSecret)
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

