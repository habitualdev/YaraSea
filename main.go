package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/hillu/go-yara/v4"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
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

func setupRoutes(port string) {
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
	log.Fatalln(http.ListenAndServe(":" + port, mux))
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

	var port string

	if _, err := os.Stat("./rules/index.yar"); errors.Is(err, os.ErrNotExist) {
		fmt.Println("Rules directory not found, cloning https://github.com/Yara-Rules/rules")
		os.Mkdir("rules",0755)
		git.PlainClone("rules", false, &git.CloneOptions{URL: "https://github.com/Yara-Rules/rules", Progress: os.Stdout})
	}

	if len(os.Args) > 2{
		log.Fatalln("Too many arguments")
	}

	if len(os.Args) == 1{
		port = "8080"
	}else {
		port = os.Args[1]
		if _, err := strconv.Atoi(port); err!= nil{
			log.Fatalln("Port not valid.")
		}
	}

	setupRoutes(port)
}
