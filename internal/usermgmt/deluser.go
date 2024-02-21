package users

import (
	"fmt"
	"log"
	"os"
	"zbld/internal/fs"
)

// DeleteTargetUser - Delete target user directory
func DeleteTargetUser(username string, force bool) {

	dirPath := usersDir + "/" + username

	if fs.IsDirExists(dirPath) {

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
