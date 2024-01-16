package users

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	configuration "zdns/internal/config"
)

// UsrConfig - Struct for new user config
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

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
func SetConfig(cfg *configuration.Config) {
	// Используйте cfg по необходимости
	userHostsTemplate = cfg.UserHostsTemplate
	userHostsPermTmpl = cfg.UserHostsPermTmpl
	userConfigTemplate = cfg.UserConfigTemplate
	usersDir = cfg.UsersDir
	usersLogDir = cfg.UsersLogDir
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

// isDirExists - Check if directory exists
func isDirExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// generateDirs - Create directory if not exists
func generateDirs(directoryPath string) {
	// Check if directory exists
	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		// Catalog does not exist, create it
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			//fmt.Println("Error creating directory:", err)
			return
		}
		fmt.Println("Directory created:", directoryPath)
	} else if err != nil {
		// Called another error
		fmt.Println("Error checking directory:", err)
		return
	} else {
		// Catalog already exists
		//fmt.Println("Directory already exists:", directoryPath)
		return
	}
}

// copyConfigFiles - Copy config files to user directory
func copyFile(srcFile, dstFile string) error {
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer func(src *os.File) {
		err := src.Close()
		if err != nil {

		}
	}(src)

	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer func(dst *os.File) {
		err := dst.Close()
		if err != nil {

		}
	}(dst)

	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	fmt.Printf("File %s copied to %s\n", srcFile, dstFile)
	return nil
}

// generateUserCatalog - Create catalogs for user
func generateUserCatalog(username string, force bool) {

	userSpaceDir := usersDir + "/" + username
	log.Println("User space directory:", userSpaceDir)

	generateDirs(usersDir)
	generateDirs(usersLogDir)
	if isDirExists(userSpaceDir) {
		log.Printf("User %s already exist. Create another user with different name. Exiting...\n", usersDir+"/"+username)
		//os.Exit(1)
		if !force {
			if askForRecreation() {
				generateDirs(userSpaceDir)
			} else {
				os.Exit(1)
			}
		}
	} else {
		generateDirs(userSpaceDir)
	}

	err := copyFile(userHostsTemplate, userSpaceDir+"/"+"hosts.txt")
	if err != nil {
		log.Println("Error copying file:", err)
		return
	}
	err = copyFile(userHostsPermTmpl, userSpaceDir+"/"+"hosts_permanent.txt")
	if err != nil {
		log.Println("Error copying file:", err)
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

// findConfigFilesWithAlias - Find config files with alias
func findConfigFilesWithAlias(rootDir, findUserAlias string) ([]string, error) {
	var configFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), "config.yml") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			if strings.Contains(string(content), findUserAlias) {
				configFiles = append(configFiles, path)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return configFiles, nil
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

// Operations with users numbers ----------------------------------------- //

// extractNumber - Extract number from username
func extractNumber(s string) (int, error) {
	// Ищем последовательность цифр в конце строки
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

// isDigit returns true if the character is a digit
func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// updateNum - Update passed number (like as port) to user postfix number
func updateNum(basePort, number int) int {
	// Заменяем последние цифры в basePort на извлеченное число
	portStr := strconv.Itoa(basePort)
	updatedPortStr := portStr[:len(portStr)-len(strconv.Itoa(number))] + strconv.Itoa(number)
	updatedPort, _ := strconv.Atoi(updatedPortStr)
	return updatedPort
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

	// Применение шаблона и запись в файл
	err = tmpl.Execute(file, newUserConfig)
	if err != nil {
		fmt.Println("Error applying template:", err)
		return
	}

	fmt.Println("Template applied and saved to", newFilename)
}

// newUserConfig - Create new user struct config with updated data
func structUsrConfig(username, useralias string, dnsPort, metricsPort, updateUserIndex int, userComment string) (UsrConfig, error) {

	config := UsrConfig{
		UserName:      username,
		UserAlias:     useralias,
		DNSPort:       dnsPort,
		MetricsPort:   metricsPort,
		LogFile:       fmt.Sprintf("users/logs/user%d.log", updateUserIndex),
		ConfigVersion: fmt.Sprintf("user%d-config", updateUserIndex),
		UserComment:   userComment,
	}

	return config, nil
}

// Externals  --------------------------------------------- //

// DeleteTargetUser - Delete target user directory
func DeleteTargetUser(username string, force bool) {

	dirPath := usersDir + "/" + username

	if isDirExists(dirPath) {

		if !force {
			// Ask user for deletion
			if !askForDeletion() {
				log.Println("User not deleted. Exit. Bye")
				os.Exit(1)
			}
		}

		err := os.RemoveAll(dirPath)
		if err != nil {
			log.Println("Error deleting directory:", err)
			return
		}
		fmt.Println("Directory deleted:", dirPath)
		os.Exit(0)
	} else {
		log.Println("User not found:", dirPath)
		os.Exit(1)
	}
}

// GenerateUserConfig - Generate user config external function
func GenerateUserConfig(usernameWithAlias string, force bool) {
	var err error
	username := extractAlias(usernameWithAlias, false)
	useralias := extractAlias(usernameWithAlias, true)

	if !isDirExists(usersDir) {
		generateDirs(usersLogDir)
	}

	if useralias == "" {
		log.Println("User alias not found. Set alias in format user_alias. Exiting...")
		os.Exit(1)
	} else {
		// Find user alias in users directory
		configFiles, err := findConfigFilesWithAlias(usersDir, useralias)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		// If alis found - Exit
		if len(configFiles) > 0 {
			log.Println("Config files containing user alias found:")
			for _, configFile := range configFiles {
				fmt.Println(configFile)
			}
			log.Println("User alias already exists. Exiting...")
			os.Exit(1)
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
	updateUserIndex := updateNum(0000, number)

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

	// Read template file
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		log.Println("Error reading template file:", err)
		return
	}

	// Read and parse template file
	tmpl, err := template.New(newFilename).Parse(string(templateContent))
	//log.Println(tmpl)
	if err != nil {
		log.Println("Error parsing template:", err)
		return
	}

	generateUserCatalog(username, force)
	applyNewConfig("users/"+username+"/"+newFilename, tmpl, newUserConfig)
	os.Exit(0)
}
