package main

import (
	"github.com/hillu/go-yara/v4"
	"io/ioutil"
	"net/http"
	_ "embed"
	"bytes"
	"fmt"
	"log"
	"os"
)
//go:embed webpages/portal.html
var indexPage []byte

//go:embed webpages/VenomAntidotum.png
var portal []byte

func printMatches(item string, m []yara.MatchRule, err error) string{
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return ""
	}
	if len(m) == 0 {
		log.Printf("%s: no matches", item)
		return ""
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	return buf.String()

}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("myFile")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}
	defer file.Close()
	fileBytes, err := ioutil.ReadAll(file)
	returnString := runYara(fileBytes,handler.Filename)
	fmt.Fprintf(w, "{\"yara_matches\":\"" + returnString + "\"}" )
}

func setupRoutes() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(indexPage)
	})
	mux.HandleFunc("/portal.png",func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(portal)
	})
	mux.HandleFunc("/upload", uploadFile)
	http.ListenAndServe(":8080", mux)
}

func runYara(fileData []byte, fileName string) string{

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	f, err := os.Open("./rules/index.yar")
	c.AddFile(f,"index")

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}
	s, _ := yara.NewScanner(r)
	var m yara.MatchRules
	err = s.SetCallback(&m).ScanMem(fileData)
	matches := printMatches(fileName, m, err)

	return matches

}

func main() {
	setupRoutes()
}