package main

import (
	hl "./handlers"
)

func main() {
	// Инициализация базы данных
	InitDB()

	// Включаем сервер и обрабатываем маршруты
	hl.initHandlers()
}
