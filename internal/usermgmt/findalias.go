package users

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func isAliasMatch(filePath string, findUserAlias string) bool {

	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(content))

	// Создание регулярного выражения для поиска строки вида "user_alias: \"sysadminkz\""
	regex := regexp.MustCompile(fmt.Sprintf(`^user_alias:\s*"%s"`, findUserAlias))

	// Поиск соответствия в содержимом файла
	if regex.Match(content) {
		return true
	} else {
		return false
	}

}

func searchConfigFile(dir string, findUserAlias string) string {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			searchConfigFile(filepath.Join(dir, file.Name()), findUserAlias)
			continue // Continue search in subdirectories
		}
		if file.Name() == "config.yml" {

			if isAliasMatch(filepath.Join(dir, file.Name()), findUserAlias) {
				fmt.Println("File", filepath.Join(dir, file.Name()), "contains user alias.")
				return filepath.Join(dir, file.Name())
			}
		}
	}
	return ""
}

// FindConfigFilesWithAlias - Find config files with alias
func FindConfigFilesWithAlias(rootDir, findUserAlias string) ([]string, error) {
	var configFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), "config.yml") {
			content, errRF := os.ReadFile(path)
			if errRF != nil {
				return err
			}

			if strings.Contains(string(content), findUserAlias) {
				configFiles = append(configFiles, path)
			}
		}

		return nil
	})

	if err != nil {
		log.Println("Error walking through directory:", err)
		return nil, err
	}

	// If alias found - Exit
	if len(configFiles) > 0 {
		for _, userConfig := range configFiles {
			fmt.Println(userConfig)
		}
		//os.Exit(0)
	} else {
		// TODO: Check from external function need Result status and exit
		fmt.Println("Result: Alias not found")
		//os.Exit(1)
	}

	return configFiles, nil
}
