package runner

import "fmt"

const version = "v0.2.0"

func ShowBanner() {
	//http://www.network-science.de/ascii/  smslant
	var banner = `
     ________ __          __         
 __ / / __/ // /_ _____  / /____ ____
/ // /\ \/ _  / // / _ \/ __/ -_) __/
\___/___/_//_/\_,_/_//_/\__/\__/_/  %s
			author by: Noel4kls	 
`
	fmt.Printf(banner, version)
}
