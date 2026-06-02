package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		v, err := fmt.Fprintf(w, "backend server recived request\n")
		if err != nil {
			fmt.Printf("Error writing response: %v\n", err)
		} else {
			fmt.Printf("Wrote %d bytes to response\n", v)
		}
	})

	fmt.Println("backend running on 8081")

	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		fmt.Printf("Error starting backend server: %v\n", err)
	}
}
