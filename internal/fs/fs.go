package fs

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

func IsOlderThanOneDay(t time.Time) bool {
	return time.Now().Sub(t) > 1*time.Minute
}

// IsFileExists - Check if file exists
func IsFileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// IsDirExists - Check if directory exists
func IsDirExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// GenerateDirs - Create directory if not exists
func GenerateDirs(directoryPath string) {
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

// CopyFile - Copy config files to user directory
func CopyFile(srcFile, dstFile string) error {
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

// DeleteOldLogFiles - Delete old log files
func DeleteOldLogFiles(logDir string, maxAge time.Duration) {
	for {
		err := filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && time.Since(info.ModTime()) > maxAge {
				if err := os.Remove(path); err != nil {
					log.Println("Error deleting file:", err)
				} else {
					log.Println("Deleted old log file:", path)
				}
			}
			return nil
		})
		if err != nil {
			log.Println("Error walking through directory:", err)
		}
		time.Sleep(24 * time.Hour) // Check every hour
	}
}

func CreateNewLogFileDaily(logPath string) {
	// Determine the current day
	currentDay := time.Now().Day()
	log.Println("Current day:", currentDay)

	// Check the current day and create a new log file if a new day begins
	for {
		// Check current time
		now := time.Now()

		// Check if the current day is different from the saved one
		if now.Day() != currentDay {
			logFileName := logPath + "_" + time.Now().Format("2006-01-02_15-04-05") + ".log"
			logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				log.Fatal("Error creating log file:", err)
			}
			defer func(logFile *os.File) {
				err := logFile.Close()
				if err != nil {

				}
			}(logFile)

			// Устанавливаем вывод логов в новый файл

			log.SetOutput(logFile)

			// Обновляем текущий день
			currentDay = now.Day()

			// Логируем информацию о создании нового файла
			log.Printf("Created new log file: %s", logFileName)
		}
		time.Sleep(24 * time.Hour) // Check every 24 hours
	}
}
