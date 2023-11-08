package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// DB представляет соединение с базой данных
var DB *sql.DB

// InitDB инициализирует соединение с базой данных
func InitDB() *sql.DB {
	// Загрузка переменных окружения из файла .env
	if err := godotenv.Load(); err != nil {
		log.Fatal("Не удалось загрузить .env файл")
	}

	// Получение значений переменных окружения
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	// Формирование строки подключения
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Подключение к базе данных MySQL
	DB, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	return DB
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	err := DB.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// AddUser добавляет нового пользователя в базу данных
func AddUser(username string, password string, email string) error {

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Подготовка запроса
	DB := InitDB()
	defer DB.Close()
	insertTransactionSQL := `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`
	statement, err := DB.Prepare(insertTransactionSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(username, string(hashedPassword), email)
	if err != nil {
		// Проверяем, что произошла ошибка дублирования ключа "email"
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			if strings.Contains(mysqlErr.Message, "email") {
				return fmt.Errorf("Пользователь с email '%s' уже зарегистрирован", email)
			} else if strings.Contains(mysqlErr.Message, "username") {
				return fmt.Errorf("Пользователь с username '%s' уже зарегистрирован", username)
			}
		}
		return err
	}
	log.Printf("Пользователь %s зарегистрирован", username)
	return nil
}

// CheckUserCredentials проверяет наличие пользователя в базе данных по логину и паролю
func CheckUserCredentials(db *sql.DB, username string, password string) bool {

	DB := InitDB()
	defer DB.Close()

	// Поиск пользователя в базе данных
	row := DB.QueryRow("SELECT password FROM users WHERE username=?", username)
	var hashedPassword string
	err := row.Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Println(err)
		return false
	}

	// Сравнение хэшированного пароля из базы данных и введенного пароля
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false
	}

	return true
}

// GetUserByUsername ищет пользователя по его имени пользователя
func GetUserByUsername(username string) (User, error) {
	DB := InitDB()
	defer DB.Close()

	var user User
	err := DB.QueryRow("SELECT id, username, email, start_depo FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Email, &user.Balance)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, errors.New("пользователь не найден")
		}
		return User{}, err
	}

	return user, nil
}

// Здесь начинаются функции
// связанные с круд операциями
// к базе данных

// DeleteTrade удаляет сделку из базы данных по ее идентификатору
func DeleteTrade(tradeID int) error {
	DB := InitDB()
	defer DB.Close()
	deleteTradeSQL := "DELETE FROM trades WHERE id = ?"

	// Удаление сделки
	_, err := DB.Exec(deleteTradeSQL, tradeID)
	if err != nil {
		return err
	}

	// Обновление идентификаторов для оставшихся сделок
	updateIDsSQL := "UPDATE trades SET id = id - 1 WHERE id > ?"
	_, err = DB.Exec(updateIDsSQL, tradeID)
	if err != nil {
		return err
	}

	return nil
}

// AddTrade добавляет новую сделку в базу данных
func AddTradeToDB(trade Trade) error {

	// Подготовка запроса
	DB := InitDB()
	defer DB.Close()
	insertTradeSQL := `INSERT INTO trades (amount, leverage, commission, position, entry_point, take_profit, stop_loss, status, forced_status, pnl, pnl_usdt, comment, image_url)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	statement, err := DB.Prepare(insertTradeSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(
		trade.AmountTrade,
		trade.LeverageLevel,
		trade.CommissionAmount,
		trade.PositionDirection,
		trade.EntryPoint,
		trade.TakeProfit,
		trade.StopLoss,
		"Активна",
		"Нет",
		0,
		0,
		trade.Comment,
		trade.ImagePath,
	)

	if err != nil {
		log.Println("Ошибка при добавлении сделки в базу данных:", err)
		return err
	}

	log.Println("Сделка успешно добавлена в базу данных")
	return nil
}

// GetTrades извлекает список сделок из базы данных
func GetTrades(userID int) ([]Trade, error) {
	DB := InitDB()
	defer DB.Close()

	rows, err := DB.Query("SELECT id, amount, leverage, commission, position, entry_point, take_profit, stop_loss, status, forced_status, pnl, pnl_usdt, comment, image_url FROM trades WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trades []Trade
	for rows.Next() {
		var trade Trade
		err := rows.Scan(
			&trade.ID,
			&trade.AmountTrade,
			&trade.LeverageLevel,
			&trade.CommissionAmount,
			&trade.PositionDirection,
			&trade.EntryPoint,
			&trade.TakeProfit,
			&trade.StopLoss,
			&trade.Status,
			&trade.ForcedStatus,
			&trade.PNL,
			&trade.PNLUSDT,
			&trade.Comment,
			&trade.ImagePath,
		)
		if err != nil {
			return nil, err
		}
		trades = append(trades, trade)
	}

	return trades, nil
}

// GetStat извлекает статистику пользователя из базы данных
func GetStat(userID int) (Stata, error) {
	DB := InitDB()
	defer DB.Close()

	query := `
        SELECT 
            t.id,
            t.amount,
            t.leverage,
            t.commission,
            t.position,
            t.entry_point,
            t.take_profit,
            t.stop_loss,
            t.status,
            t.forced_status,
            t.pnl,
            t.pnl_usdt,
            t.comment,
            t.image_url,
            d.correct_depo
        FROM trades t
        LEFT JOIN deposit d ON t.user_id = d.user_id
        WHERE t.user_id = ?`

	rows, err := DB.Query(query, userID)
	if err != nil {
		return Stata{}, err
	}
	defer rows.Close()

	var stat Stata
	for rows.Next() {
		var trade Trade
		err := rows.Scan(
			&trade.ID,
			&trade.AmountTrade,
			&trade.LeverageLevel,
			&trade.CommissionAmount,
			&trade.PositionDirection,
			&trade.EntryPoint,
			&trade.TakeProfit,
			&trade.StopLoss,
			&trade.Status,
			&trade.ForcedStatus,
			&trade.PNL,
			&trade.PNLUSDT,
			&trade.Comment,
			&trade.ImagePath,
			&stat.CorrectDepo,
		)
		if err != nil {
			return Stata{}, err
		}
		stat.Trades = append(stat.Trades, trade)
	}

	return stat, nil
}

func GetTradeProfits(userID int) ([]float64, error) {
	DB := InitDB()
	defer DB.Close()

	// Определите начальную и конечную даты для последних 30 дней
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	// Создайте карту для хранения прибыли по дням
	profitsByDay := make(map[string]float64)

	// Заполните карту данными из базы данных
	rows, err := DB.Query("SELECT DATE_FORMAT(created_at, '%Y-%m-%d'), pnl_usdt FROM trades WHERE user_id = ? AND DATE_FORMAT(created_at, '%Y-%m-%d') BETWEEN ? AND ?", userID, startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var createdAtStr string
		var pnl float64
		err := rows.Scan(&createdAtStr, &pnl)
		if err != nil {
			return nil, err
		}

		profitsByDay[createdAtStr] = pnl
	}

	// Создайте массив значений прибыли за последние 30 дней
	var profits []float64
	currentDate := startDate
	for currentDate.Before(endDate) || currentDate.Equal(endDate) {
		if profit, found := profitsByDay[currentDate.Format("2006-01-02")]; found {
			profits = append(profits, profit)
		} else {
			profits = append(profits, 0.00)
		}
		currentDate = currentDate.AddDate(0, 0, 1)
	}

	return profits, nil
}

// UpdateTradeStatus обновляет статус сделки в базе данных по ее идентификатору
func UpdateTradeStatus(tradeID int, newStatus string) error {
	DB := InitDB()
	defer DB.Close()
	updateTradeStatusSQL := "UPDATE trades SET status = ? WHERE id = ?"

	_, err := DB.Exec(updateTradeStatusSQL, newStatus, tradeID)
	if err != nil {
		return err
	}

	return nil
}

// UpdateTradeComment обновляет комментарий сделки в базе данных по ее идентификатору
func UpdateTradeComment(tradeID int, newComment string) error {
	DB := InitDB()
	defer DB.Close()
	updateTradeCommentSQL := "UPDATE trades SET comment = ? WHERE id = ?"

	_, err := DB.Exec(updateTradeCommentSQL, newComment, tradeID)
	if err != nil {
		return err
	}

	return nil
}

// UpdateTradeCommission обновляет комментарий сделки в базе данных по ее идентификатору
func UpdateTradeCommission(tradeID int, newCommission string) error {
	DB := InitDB()
	defer DB.Close()
	updateTradeCommissionSQL := "UPDATE trades SET commission = ? WHERE id = ?"

	_, err := DB.Exec(updateTradeCommissionSQL, newCommission, tradeID)
	if err != nil {
		return err
	}

	return nil
}

// UpdateTradePNL обновляет PNLUSDT сделки в базе данных по ее идентификатору
func UpdateTradePNL(tradeID int, PNLUSDT string) error {
	DB := InitDB()
	defer DB.Close()
	updateTradePNLSQL := "UPDATE trades SET pnl_usdt = ? WHERE id = ?"

	_, err := DB.Exec(updateTradePNLSQL, PNLUSDT, tradeID)
	if err != nil {
		return err
	}

	return nil
}

// Получение начального депозита пользователя из базы данных
func GetInitialDeposit(userId int) (float64, error) {
	DB := InitDB()
	defer DB.Close()

	var initialDeposit float64
	err := DB.QueryRow("SELECT depo FROM users WHERE id = ?", userId).Scan(&initialDeposit)
	if err != nil {
		return 0, err
	}

	return initialDeposit, nil
}

// GetPNLUSDTForLast30Days получает прибыль/убыток пользователя за последние 30 дней
func GetPNLUSDTForLast30Days(userId int) ([]float64, error) {
	DB := InitDB()
	defer DB.Close()

	// Определяем текущую дату и дату 30 дней назад
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	// Подготовьте SQL-запрос для выборки прибыли/убытка пользователя за последние 30 дней
	query := `
		SELECT pnl_usdt
		FROM trades
		WHERE user_id = ? AND created_at BETWEEN ? AND ?
	`

	rows, err := DB.Query(query, userId, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pnlUSDT []float64
	for rows.Next() {
		var pnl float64
		err := rows.Scan(&pnl)
		if err != nil {
			return nil, err
		}
		pnlUSDT = append(pnlUSDT, pnl)
	}

	return pnlUSDT, nil
}
