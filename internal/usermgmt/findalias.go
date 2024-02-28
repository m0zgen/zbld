package users

import (
	"fmt"
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

	contentStr := string(content)

	// Создание регулярного выражения для поиска строки вида "user_alias: \"sysadminkz\""
	regex := regexp.MustCompile(fmt.Sprintf(`user_alias:\s*"%s"`, findUserAlias))

	// Поиск соответствия в содержимом файла
	if regex.MatchString(contentStr) {
		return true
	} else {
		return false
	}

}

func SearchConfigFile(dir string, findUserAlias string) []string {
	var configFiles []string

	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			// Объединяем результаты рекурсивного вызова с текущими configFiles
			configFiles = append(configFiles, SearchConfigFile(filepath.Join(dir, file.Name()), findUserAlias)...)
			continue // Continue search in subdirectories
		}
		if file.Name() == "config.yml" {
			if isAliasMatch(filepath.Join(dir, file.Name()), findUserAlias) {
				//fmt.Println("File:", filepath.Join(dir, file.Name()), "contains user alias.")
				configFiles = append(configFiles, filepath.Join(dir, file.Name()))
			}
		}
	}
	return configFiles
}

// FindConfigFilesWithAlias - Find config files with alias
func FindConfigFilesWithAlias(rootDir, findUserAlias string) ([]string, error) {
	var configFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), "config.yml") {

			if isAliasMatch(path, findUserAlias) {
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
		os.Exit(0)
	} else {
		// TODO: Check from external function need Result status and exit
		fmt.Println("Result: Alias not found")
		os.Exit(1)
	}

	return configFiles, nil
}
