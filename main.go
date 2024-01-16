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

func main() {
    fmt.Println("KEK")

    tmpl := template.Must(template.ParseFiles("view.html"))
    clickthroughPage := template.Must(template.ParseFiles("reveal.html"))

    router := chi.NewRouter()
    router.Get("/", func(w http.ResponseWriter, r *http.Request) {
        data := struct {
            Secret string
        }{
            Secret: "SecretLinks",
        }
        tmpl.Execute(w, data)
    })
    router.Post("/secret", func(w http.ResponseWriter, r *http.Request) {
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
    })
    router.Get("/secret/{id}", func(w http.ResponseWriter, r *http.Request) {
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
    })
    router.Post("/secret/{id}", func(w http.ResponseWriter, r *http.Request) {
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
    })

    http.ListenAndServe(":8080", router)
}
