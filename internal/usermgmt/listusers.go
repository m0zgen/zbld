package users

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ListUsers - List users from users directory
func ListUsers(dir string, summary bool) {
	files, err := os.ReadDir(dir)
	if err != nil {
		fmt.Println("Error read catalog:", err)
		return
	}

	for _, file := range files {
		if file.IsDir() && strings.HasPrefix(file.Name(), "user") {
			userName, userAlias, userDNSPort, userComment, err := readConfig(filepath.Join(dir, file.Name(), "config.yml"))
			if err != nil {
				fmt.Printf("Ошибка чтения файла конфигурации для пользователя %s: %v\n", file.Name(), err)
				continue
			}
			if summary {
				fmt.Printf("%s-%s,%s\n", userName, userAlias, userDNSPort)
			} else {
				fmt.Printf("UserName: %s, Alias: %s, Port: %s, Comment: %s\n", userName, userAlias, userDNSPort, userComment)
			}
		}
	}
	os.Exit(0)
}
