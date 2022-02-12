//hello.go
package main

import "C"
import "fmt"

func main() {
	Hello("hello")
}

//export Hello
func Hello(name string) {
	fmt.Println("output:", name)
}
