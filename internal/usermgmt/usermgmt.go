package users

import (
	"bufio"
	"fmt"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	configuration "zbld/internal/config"
	"zbld/internal/fs"
)

// UsrConfig - Template struct for new user config
type UsrConfig struct {
	DNSPort       int
	MetricsPort   int
	LogFile       string
	ConfigVersion string
	UserName      string
	UserAlias     string
	UserComment   string
}

// Config variables ----------------------------------------------------- //

var userHostsTemplate string
var userHostsPermTmpl string
var userConfigTemplate string
var usersDir string
var usersLogDir string
var userDirPermissionFor string

// UserConfig - Struct for export yml config params (ListUsers function)
type UserConfig struct {
	UserName    string `yaml:"user_name"`
	UserAlias   string `yaml:"user_alias"`
	UserComment string `yaml:"user_comment"`
	UserDNSPort string `yaml:"dns_port"`
}

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
func SetConfig(cfg *configuration.Config) {
	// Bind config variables
	userHostsTemplate = cfg.UserHostsTemplate
	userHostsPermTmpl = cfg.UserHostsPermTmpl
	userConfigTemplate = cfg.UserConfigTemplate
	usersDir = cfg.UsersDir
	usersLogDir = cfg.UsersLogDir
	userDirPermissionFor = cfg.UserDirPermissionFor
	// ...
}

// Operations with file system ------------------------------------------- //

// askForRecreation - Ask for recreation directory
func askForRecreation() bool {
	fmt.Print("Directory already exists. Do you want to recreate it? (Y/N): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.ToUpper(strings.TrimSpace(scanner.Text()))
	return answer == "Y"
}

// askForDeletion - Ask user for deletion directory
func askForDeletion() bool {
	fmt.Print("User already exists. Do you want to delete it? (Y/N): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.ToUpper(strings.TrimSpace(scanner.Text()))
	return answer == "Y"
}

// generateUserCatalog - Create catalogs for user
func generateUserCatalog(username string, force bool) {

	userSpaceDir := usersDir + "/" + username
	log.Println("User space directory:", userSpaceDir)

	fs.GenerateDirs(usersDir)
	fs.GenerateDirs(usersLogDir)
	if fs.IsDirExists(userSpaceDir) {
		log.Printf("User %s already exist. Create another user with different name. Exiting...\n", usersDir+"/"+username)
		//os.Exit(1)
		if !force {
			if askForRecreation() {
				fs.GenerateDirs(userSpaceDir)
			} else {
				os.Exit(1)
			}
		}
	} else {
		fs.GenerateDirs(userSpaceDir)
	}

	err := fs.CopyFile(userHostsTemplate, userSpaceDir+"/"+"hosts.txt")
	if err != nil {
		log.Println("Error copying file:", err)
		return
	}
	err = fs.CopyFile(userHostsPermTmpl, userSpaceDir+"/"+"hosts-permanent.txt")
	if err != nil {
		log.Println("Error copying file:", err)
		return
	}

	err = fs.SetPermissions(userDirPermissionFor, userSpaceDir)
	if err != nil {
		log.Println("Error setting permissions:", err)
		return
	}

}

// Operations wit users names and aliases -------------------------------- //

// getNextUserName - Get next username from users catalog
func getNextUserName(basePath, baseName string) (string, error) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return "", err
	}

	existingNumbers := make(map[int]struct{})

	for _, entry := range entries {
		if entry.IsDir() {
			dirName := entry.Name()
			re := regexp.MustCompile(baseName + `(\d+)`)
			match := re.FindStringSubmatch(dirName)
			if match != nil {
				numberStr := match[1]
				number, err := strconv.Atoi(numberStr)
				if err == nil {
					existingNumbers[number] = struct{}{}
				}
			}
		}
	}

	if len(existingNumbers) == 0 {
		return baseName + "1", nil
	}

	var numbers []int
	for num := range existingNumbers {
		numbers = append(numbers, num)
	}

	sort.Ints(numbers)

	for i := 1; i <= len(numbers); i++ {
		if numbers[i-1] != i {
			return baseName + strconv.Itoa(i), nil
		}
	}

	return baseName + strconv.Itoa(len(numbers)+1), nil
}

// extractAlias - Extract alias from username
func extractAlias(username string, extractAlias bool) string {

	parts := strings.Split(username, "_")
	if len(parts) == 2 {
		user := parts[0]
		alias := parts[1]
		if extractAlias {
			log.Println("User:", user)
			log.Println("Alias:", alias)
			return alias
		} else {
			return user
		}
	} else {
		return ""
	}

}

// readConfig - Read config file and return username and useralias for ListUsers function
func readConfig(filePath string) (string, string, string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
			return
		}
	}(file)

	var config UserConfig
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return "", "", "", "", err
	}

	return config.UserName, config.UserAlias, config.UserDNSPort, config.UserComment, nil
}

// Operations with users numbers ----------------------------------------- //

// isDigit returns true if the character is a digit
func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// updateNum - Update passed number (like as port) to user postfix number
func updateNum(basePort, number int) int {
	if number <= 9999 {
		// Change last digits in basePort etc. params in config to extracted number
		portStr := strconv.Itoa(basePort)
		if portStr == "0" {
			return number
		}
		updatedPortStr := portStr[:len(portStr)-len(strconv.Itoa(number))] + strconv.Itoa(number)
		updatedPort, _ := strconv.Atoi(updatedPortStr)
		return updatedPort
	} else {
		log.Println("Number is too big. End of reach users. Exiting...")
		os.Exit(1)
		return 0
	}
}

// extractNumber - Extract number from username
func extractNumber(s string) (int, error) {
	// Find last digit index in username
	lastDigitIndex := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		if !isDigit(s[i]) {
			break
		}
		lastDigitIndex = i
	}

	// Extract number from string and convert to int
	number, err := strconv.Atoi(s[lastDigitIndex:])
	if err != nil {
		return 0, err
	}

	return number, nil
}

// Operations with users config ----------------------------------------- //

// applyNewConfig - Apply new config for user (create files and write data to config)
func applyNewConfig(newFilename string, tmpl *template.Template, newUserConfig UsrConfig) {
	// Create new file for record
	file, err := os.Create(newFilename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
			return
		}
	}(file)

	// Apply template and write to file
	err = tmpl.Execute(file, newUserConfig)
	if err != nil {
		fmt.Println("Error applying template:", err)
		return
	}

	// Template applied and saved to newFilename
	fmt.Println("Config:", newFilename)
	err = fs.SetPermissions(userDirPermissionFor, newFilename)
	if err != nil {
		return
	}
	//os.Exit(0)
}

// newUserConfig - Create new user struct config with updated data
func structUsrConfig(username, useralias string, dnsPort, metricsPort, updateUserIndex int, userComment string) (UsrConfig, error) {

	config := UsrConfig{
		UserName:      username,
		UserAlias:     useralias,
		DNSPort:       dnsPort,
		MetricsPort:   metricsPort,
		LogFile:       fmt.Sprintf("user%d_log", updateUserIndex),
		ConfigVersion: fmt.Sprintf("user%d-config", updateUserIndex),
		UserComment:   userComment,
	}

	return config, nil
}

// Externals  --------------------------------------------- //

// GenerateUserConfig - Generate user config external function
func GenerateUserConfig(usernameWithAlias string, force bool) {
	var err error
	username := extractAlias(usernameWithAlias, false)
	useralias := extractAlias(usernameWithAlias, true)

	if !fs.IsDirExists(usersDir) {
		fs.GenerateDirs(usersLogDir)
	}

	if useralias == "" {
		log.Println("User alias not found. Set alias in format user_alias. Exiting...")
		os.Exit(1)
	} else {
		// Find user alias in users directory
		//configFiles, errF := FindConfigFilesWithAlias(usersDir, useralias)
		configFiles := SearchConfigFile(usersDir, useralias)
		//if errF != nil {
		//	fmt.Println("Error:", err)
		//	return
		//}

		if !force {
			// If alis found - Exit
			if len(configFiles) > 0 {
				log.Println("User alias already exists:", useralias)
				for _, configFile := range configFiles {
					fmt.Println("Config:", configFile)
				}
				fmt.Println("Existing user:", useralias)
				os.Exit(1)
			}
		}
	}

	// Check if username is numbered
	if username == "" {
		log.Println("Passed user name not found. Maybe need number in user name in format user_alias? Exiting...")
		os.Exit(1)
	}

	// Is username does not have digit,add digit in to username
	if !isDigit(username[len(username)-1]) {
		// Scan users folder and set new username with next user number
		username, err = getNextUserName(usersDir, "user")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		log.Println("New user name:", username)
	} else {
		//log.Println("User is Numbered")
		// If username not contains "user" set default name
		if username[:4] != "user" {
			username, err = getNextUserName(usersDir, "user")
			if err != nil {
				log.Println("Error:", err)
				os.Exit(1)
			}

		} else {
			username = extractAlias(usernameWithAlias, false)
		}
	}

	userComment := "passed_alias-" + useralias + "_passed_name-" + username

	// Path to template file
	templatePath := userConfigTemplate
	// New config filename
	newFilename := "config.yml"

	// Extract number from username
	number, err := extractNumber(username)
	if err != nil {
		fmt.Println("Error extracting number:", err)
		return
	}

	log.Println("User postfix number:", number)

	// Update default ports and user index
	updatedDNSPort := updateNum(50000, number)
	updateMetricsPort := updateNum(40000, number)
	updateUserIndex := updateNum(0, number)

	// Apply new config for new user with updated data
	//newUserConfig := UsrConfig{
	//	UserName:      username,
	//	UserAlias:     useralias,
	//	DNSPort:       updatedDNSPort,
	//	MetricsPort:   updateMetricsPort,
	//	LogFile:       "users/logs/user" + strconv.Itoa(updateUserIndex) + ".log",
	//	ConfigVersion: "user" + strconv.Itoa(updateUserIndex) + "-config",
	//}
	newUserConfig, err := structUsrConfig(username, useralias, updatedDNSPort, updateMetricsPort, updateUserIndex, userComment)
	if err != nil {
		fmt.Println("Error:", err)
		//return
		os.Exit(1)
	}

	// Process template file and apply new config

	// Read template file
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		log.Println("Error reading template file:", err)
		//return
		os.Exit(1)
	}

	// Read and parse template file
	tmpl, err := template.New(newFilename).Parse(string(templateContent))
	//log.Println(tmpl)
	if err != nil {
		log.Println("Error parsing template:", err)
		//return
		os.Exit(1)
	}

	generateUserCatalog(username, force)
	applyNewConfig("users/"+username+"/"+newFilename, tmpl, newUserConfig)
	fmt.Println("UserName:", username)
	fmt.Println("Alias:", useralias)
	fmt.Println("Port:", strconv.Itoa(updatedDNSPort))
	fmt.Printf("Summary: %s-%s,%s\n", username, useralias, strconv.Itoa(updatedDNSPort))

	os.Exit(0)
}
