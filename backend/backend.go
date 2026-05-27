package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/",func(w http.ResponseWriter, r *http.Request) {
 			
		fmt.Fprintf(w,"backend server recived request\n")
	})

	fmt.Println("backend running on 8081")

	http.ListenAndServe(":8081",nil)
}