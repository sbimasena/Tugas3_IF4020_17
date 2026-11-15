package strictjson_test

import (
	"fmt"

	"kelompok17/internal/strictjson"
)

func ExampleUnmarshal() {
	var v struct {
		A string `json:"a"`
	}
	fmt.Println(strictjson.Unmarshal([]byte(`{"a":"x"}`), &v), v.A)
	fmt.Println(strictjson.Unmarshal([]byte(`{"a":"x","a":"y"}`), &v))
	// Output:
	// <nil> x
	// json: $: duplicate key "a"
}
