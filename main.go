package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

func allData(url string) {
	// Get request
	req, err := http.Get(url)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")

	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(req.Body)

	if err != nil {
		log.Fatalln(err)
	}

	// JSON unmarshalling
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	data := result["data"].([]interface{})

	for n, value := range data {
		cveDetail := value.(map[string]interface{})["cve"]
		description := value.(map[string]interface{})["description"]
		assigner := value.(map[string]interface{})["assigner"]
		severity := value.(map[string]interface{})["severity"]

		fmt.Print("<*>---------------------------------------------------------<*>\n\n")
		fmt.Printf("CVE ID %v: %v\n", n+1, cveDetail)
		fmt.Printf("DESCRIPTION: %v\n", description)
		fmt.Printf("ASSIGNER: %v\n", assigner)
		color.Blue("SEVERITY: %v\n\n", severity)

	}
}

func dayCve(url string) {
	req, err := http.Get(url)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")

	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// JSON unmarshalling
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	data := result["data"].([]interface{})
	for n, value := range data {
		cveDetail := value.(map[string]interface{})["cve"]
		fmt.Printf("[%v]  ➜  %v\n", n+1, cveDetail)
	}

}

func weeklyCve(url string) {
	req, err := http.Get(url)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")

	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// JSON unmarshalling
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	data := result["data"].([]interface{})
	for n, value := range data {
		cveDetail := value.(map[string]interface{})["cve"]
		fmt.Printf("[%v]  ➜  %v\n", n+1, cveDetail)
	}

}

func sevAsg(url string) {
	req, err := http.Get(url)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")

	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// JSON unmarshalling
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	data := result["data"].([]interface{})

	for _, value := range data {
		cveDetail := value.(map[string]interface{})["cve"]
		assigner := value.(map[string]interface{})["assigner"]
		severity := value.(map[string]interface{})["severity"]

		fmt.Print("<*>---------------------------------------------------------<*>\n\n")
		fmt.Printf("[*] CVE ID: %v\n", cveDetail)
		fmt.Printf("Severity: %v\n", severity)
		color.Blue("Assigner: %v\n\n", assigner)
	}
}

func oneDetail(dayUrl string, weekUrl string, id string) {

	fetchInfo := id
	dayurl, dayErr := http.Get(dayUrl)
	weekurl, weekErr := http.Get(weekUrl)

	weekurl.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")
	dayurl.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0")

	if dayErr != nil {
		log.Fatalln(dayErr)
	}
	if weekErr != nil {
		log.Fatalln(weekErr)
	}

	dayBody, err := ioutil.ReadAll(dayurl.Body)
	if err != nil {
		log.Fatalln(err)
	}
	weekBody, err := ioutil.ReadAll(weekurl.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// JSON unmarshalling
	var dayResult map[string]interface{}
	json.Unmarshal([]byte(dayBody), &dayResult)
	dayData := dayResult["data"].([]interface{})

	// JSON unmarshalling
	var WeekResult map[string]interface{}
	json.Unmarshal([]byte(weekBody), &WeekResult)
	weekData := WeekResult["data"].([]interface{})

	for _, dayValue := range dayData {
		dayCveDetail := dayValue.(map[string]interface{})["cve"]
		description := dayValue.(map[string]interface{})["description"]
		assigner := dayValue.(map[string]interface{})["assigner"]
		severity := dayValue.(map[string]interface{})["severity"]
		publishDate := dayValue.(map[string]interface{})["publishedDate"]
		if fetchInfo == dayCveDetail {
			fmt.Print("\n<*>---------------------------------------------------------<*>\n\n")
			fmt.Printf("CVE ID: %v\n", dayCveDetail)
			fmt.Printf("ASSIGNER: %v\n", assigner)
			color.Green("DESCRIPTION: %v\n", description)
			fmt.Printf("SEVERITY: %v\n", severity)
			fmt.Printf("PUBLISHED-DATE: %v\n", publishDate)
			switch severity {
			case "CRITICAL":
				color.HiRed("[*] Found CRITICAL SEVERITY\n\n")
			case "HIGH":
				color.Red("[*] Found HIGH SEVERITY\n\n")
			case "MEDIUM":
				color.Yellow("[*] Found SEVERITY MEDIUM\n\n")
			}
			fmt.Print("<*>---------------------------------------------------------<*>\n\n")
			os.Exit(0)
		}
	}
	for _, weekValue := range weekData {
		weekCveDetail := weekValue.(map[string]interface{})["cve"]
		description := weekValue.(map[string]interface{})["description"]
		assigner := weekValue.(map[string]interface{})["assigner"]
		severity := weekValue.(map[string]interface{})["severity"]
		publishDate := weekValue.(map[string]interface{})["publishedDate"]
		if fetchInfo == weekCveDetail {
			fmt.Print("\n<*>---------------------------------------------------------<*>\n\n")
			fmt.Printf("CVE ID: %v\n", weekCveDetail)
			fmt.Printf("ASSIGNER: %v\n", assigner)
			color.Green("DESCRIPTION: %v\n", description)
			fmt.Printf("SEVERITY: %v\n", severity)
			fmt.Printf("PUBLISHED-DATE: %v\n\n", publishDate)
			switch severity {
			case "CRITICAL":
				color.HiRed("[*] Found CRITICAL SEVERITY\n\n")
			case "HIGH":
				color.Red("[*] Found HIGH SEVERITY\n\n")
			case "MEDIUM":
				color.Yellow("[*] Found SEVERITY MEDIUM\n\n")
			}
			fmt.Print("<*>---------------------------------------------------------<*>\n\n")
			os.Exit(0)
		}
	}

}

func main() {

	Banner()

	if len(os.Args) == 1 {
		color.HiRed("Wrong! Please Run: %v --help/-h\n\n", os.Args[0])
	}

	var singleCve string
	cve := flag.String("cve", "", "Only CVE ID. (Usage: --cve day, --cve week)")
	allInfo := flag.Bool("all", false, "Detail like CVE ID, Description, Assigner, Severity (Usage: --cve day/week -all)")
	sevInfo := flag.Bool("sa", false, "For Severity and Assigner (Usage: --cve day/week --sa)")
	flag.StringVar(&singleCve, "info", "", "All info about specific CVE (Usage: -info CVE-XXXX-XXXX)")
	flag.Parse()

	if *cve == "day" {
		url := "https://cvetrends.com/api/cves/24hrs"
		if *allInfo == true {
			allData(url)
			os.Exit(0)
		} else if *sevInfo == true {
			sevAsg(url)
			os.Exit(0)
		}
		dayCve(url)
	} else if *cve == "week" {
		url := "https://cvetrends.com/api/cves/order-by-tweets-7days"
		if *allInfo == true {
			allData(url)
			os.Exit(0)
		} else if *sevInfo == true {
			sevAsg(url)
			os.Exit(0)
		}
		weeklyCve(url)
		os.Exit(0)
	}
	if singleCve != "" {
		dayurl := "https://cvetrends.com/api/cves/24hrs"
		weekurl := "https://cvetrends.com/api/cves/order-by-tweets-7days"
		id := strings.ToUpper(singleCve)
		oneDetail(dayurl, weekurl, id)

	}

}

func Banner() {
	v := `
		   ______       _ _              
		  (_____ \     | | |             
  ____ _   _ _____ _____) )   _| | | _____  ____ 
 / ___) | | | ___ |  ____/ | | | | || ___ |/ ___)
( (___ \ V /| ____| |    | |_| | | || ____| |    
 \____) \_/ |_____)_|    |____/ \_)_)_____)_|    
				
                   		@ransomsec
						`
	fmt.Println(v)
}
