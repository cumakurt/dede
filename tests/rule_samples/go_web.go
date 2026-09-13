// Static-only security regression samples; never execute this package.
package websample

import (
    "database/sql"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
)

func queries(req *http.Request, db *sql.DB) {
    name := req.URL.Query().Get("name")
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    // ruleid: dede.go.web.sql-injection
    db.Query(query)
    // ruleid: dede.go.web.sql-injection
    db.QueryContext(req.Context(), query)
    // ok: dede.go.web.sql-injection
    db.Query("SELECT * FROM users WHERE name = ?", name)
    // ok: dede.go.web.sql-injection
    db.QueryContext(req.Context(), "SELECT * FROM users WHERE name = ?", name)
}

func commands(req *http.Request) {
    command := req.FormValue("cmd")
    // ruleid: dede.go.web.command-injection
    exec.Command("sh", "-c", command)
    // ruleid: dede.go.web.command-injection
    exec.CommandContext(req.Context(), "sh", "-c", command)
    // ok: dede.go.web.command-injection
    exec.Command("printf", "%s", command)
}

func paths(req *http.Request) {
    name := req.URL.Query().Get("name")
    // ruleid: dede.go.web.path-traversal
    os.ReadFile(name)
    cleaned := filepath.Clean(name)
    // ruleid: dede.go.web.path-traversal
    os.Open(cleaned)
    // ok: dede.go.web.path-traversal
    os.Open("/srv/data/fixed.txt")
}
