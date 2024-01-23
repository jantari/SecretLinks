package main

import (
    "fmt"

    "html/template"
    "net/http"
    "encoding/json"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type Secret struct {
    Secret       string `json:"secret"`
    Views        int    `json:"views"`
    ClickThrough bool   `json:"click"`
}

var SecretStore = make(map[uuid.UUID]Secret)

var tmpl = template.Must(template.ParseFiles("view.html"))
var clickthroughPage = template.Must(template.ParseFiles("reveal.html"))

func main() {
    fmt.Println("SecretLinks")

    router := chi.NewRouter()
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("SecretLinks"))
    })
    router.Route("/api", func(r chi.Router) {
        router.Post("/secret", newSecret)
    })
    router.Get("/secret/{id}", getSecret)
    router.Post("/secret/{id}", clickthroughRetrieveSecret)

    http.ListenAndServe(":8080", router)
}

func getSecret(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    secretId, err := uuid.Parse(id)
    if err != nil {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    retrievedSecret, ok := SecretStore[secretId]
    if ok && retrievedSecret.Views > 0 {
        if !retrievedSecret.ClickThrough {
            // Clickthrough not enabled, show secret immediately
            retrievedSecret.Views--
            SecretStore[secretId] = retrievedSecret
            tmpl.Execute(w, retrievedSecret)
        } else {
            // Clickthrough enabled, return page with button to retrieve (additional request)
            data := struct {
                SecretId string
            } {
                SecretId: id,
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
    secretId, err := uuid.Parse(id)
    if err != nil {
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }
    retrievedSecret, ok := SecretStore[secretId]
    if ok && retrievedSecret.Views > 0 {
        retrievedSecret.Views--
        SecretStore[secretId] = retrievedSecret
        tmpl.Execute(w, retrievedSecret)
    }
}

func newSecret(w http.ResponseWriter, r *http.Request) {
    payload := &Secret{}
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
    SecretStore[id] = *payload

    w.Write([]byte(fmt.Sprintf("%v", id)))
}

