package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Trade struct {
	ID                float64
	AmountTrade       float64
	LeverageLevel     float64
	CommissionAmount  float64
	PositionDirection string
	EntryPoint        float64
	TakeProfit        float64
	Status            string
	ForcedStatus      string
	PNL               float64
	PNLUSDT           float64
	StopLoss          float64
	Comment           string
	ImagePath         string
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Stata struct {
	CorrectDepo float64
	Trades      []Trade
}

func GetTradesHandler(w http.ResponseWriter, r *http.Request) {

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	trades, err := GetTrades(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразование списка сделок в формат JSON
	tradesJSON, err := json.Marshal(trades)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка заголовков и отправка ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tradesJSON)
}

func GetStatHandler(w http.ResponseWriter, r *http.Request) {

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	stat, err := GetStat(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразование списка сделок в формат JSON
	statJSON, err := json.Marshal(stat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка заголовков и отправка ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(statJSON)
}

func GetTradeProfitsHandler(w http.ResponseWriter, r *http.Request) {
	// Извлеките параметры из URL
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор пользователя", http.StatusBadRequest)
		return
	}

	// Вызов функции GetTradeProfits для извлечения прибыли или убытка за последние 30 дней
	profits, err := GetTradeProfits(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразование прибыли/убытка в формат JSON
	profitsJSON, err := json.Marshal(profits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка заголовков и отправка ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(profitsJSON)
}

func AddTradeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Получите данные сделки из формы
	r.ParseMultipartForm(10 << 20) // Максимальный размер файла: 10MB
	trade := Trade{
		AmountTrade:       parseFloat64(r.FormValue("amountTrade")),
		LeverageLevel:     parseFloat64(r.FormValue("leverageLevel")),
		CommissionAmount:  parseFloat64(r.FormValue("commissionAmount")),
		PositionDirection: r.FormValue("positionDirection"),
		EntryPoint:        parseFloat64(r.FormValue("entryPoint")),
		TakeProfit:        parseFloat64(r.FormValue("takeProfit")),
		StopLoss:          parseFloat64(r.FormValue("stopLoss")),
		Comment:           r.FormValue("comment"),
	}

	// Проверка и обработка изображения
	file, handler, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Ошибка при загрузке изображения", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Генерация уникального имени файла на сервере
	fileExt := filepath.Ext(handler.Filename)
	newFileName := strconv.FormatInt(time.Now().Unix(), 10) + fileExt
	filePath := filepath.Join("uploads", newFileName)

	// Создание файла на сервере и запись в него изображения
	newFile, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Ошибка при сохранении изображения", http.StatusInternalServerError)
		return
	}
	defer newFile.Close()
	io.Copy(newFile, file)

	// Установка пути к сохраненному изображению
	trade.ImagePath = filePath
	err = AddTradeToDB(trade)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка ответа с путем к сохраненному изображению
	jsonResponse, err := json.Marshal(trade)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

// Удаление сделки
func DeleteTradeHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка метода запроса
	if r.Method != http.MethodDelete {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	tradeID, err := strconv.Atoi(vars["tradeId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	// Вызовите функцию для удаления сделки из базы данных по tradeID
	if err := DeleteTrade(tradeID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте ответ об успешном удалении сделки
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Сделка успешно удалена"))
}

func parseFloat64(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0.0
	}
	return f
}

// Обновление статуса
func UpdateTradeStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	tradeID, err := strconv.Atoi(vars["tradeId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	// Прочитайте новый статус из тела запроса
	var requestBody struct {
		Status string `json:"Status"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Вызовите функцию для обновления статуса сделки в базе данных
	if err := UpdateTradeStatus(tradeID, requestBody.Status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте ответ об успешном обновлении статуса
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Статус сделки успешно обновлен"))
}

// Обновление комментария
func UpdateTradeCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	tradeID, err := strconv.Atoi(vars["tradeId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	// Прочитайте новый статус из тела запроса
	var requestBody struct {
		Comment string `json:"Comment"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Вызовите функцию для обновления статуса сделки в базе данных
	if err := UpdateTradeComment(tradeID, requestBody.Comment); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте ответ об успешном обновлении статуса
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Комментарий сделки успешно обновлен"))
}

// Обновление коммиссии
func UpdateTradeCommissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	tradeID, err := strconv.Atoi(vars["tradeId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	// Прочитайте новый статус из тела запроса
	var requestBody struct {
		CommissionAmount string `json:"Commission"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Вызовите функцию для обновления статуса сделки в базе данных
	if err := UpdateTradeCommission(tradeID, requestBody.CommissionAmount); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте ответ об успешном обновлении статуса
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Коммиссия сделки успешно обновлена"))
}

// Обновление коммиссии
func UpdateTradePNLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Извлеките параметры из URL
	vars := mux.Vars(r)
	tradeID, err := strconv.Atoi(vars["tradeId"])
	if err != nil {
		http.Error(w, "Неверный идентификатор сделки", http.StatusBadRequest)
		return
	}

	// Прочитайте новый статус из тела запроса
	var requestBody struct {
		PNLUSDT string `json:"PNLUSDT"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Вызовите функцию для обновления статуса сделки в базе данных
	if err := UpdateTradePNL(tradeID, requestBody.PNLUSDT); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте ответ об успешном обновлении статуса
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Коммиссия сделки успешно обновлена"))
}

// Обработчик для получения начального депозита пользователя
func GetInitialDepositHandler(w http.ResponseWriter, r *http.Request) {
	// Получите идентификатор пользователя из запроса (например, из параметров URL)
	userIdStr := r.URL.Query().Get("userId")
	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Получите начальный депозит пользователя из базы данных
	initialDeposit, err := GetInitialDeposit(userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте начальный депозит в формате JSON в ответе
	w.Header().Set("Content-Type", "application/json")
	responseData := map[string]float64{"deposit": initialDeposit}
	json.NewEncoder(w).Encode(responseData)
}

// Обработчик для получения сделок пользователя за последние 30 дней и их прибыли/убытка
func GetTradesForLast30DaysHandler(w http.ResponseWriter, r *http.Request) {
	// Получите идентификатор пользователя из запроса (например, из параметров URL)
	userIdStr := r.URL.Query().Get("userId")
	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Получите список сделок пользователя за последние 30 дней из базы данных
	trades, err := GetPNLUSDTForLast30Days(userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправьте список сделок в формате JSON в ответе
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trades)
}

// Здесь у нас будет
// код обработчиков связанных
// с авторизацией пользователей
var jwtSecret = []byte("my_secret_key")

type SignupRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthResponse struct {
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	User         interface{} `json:"user"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type User struct {
	ID       float64
	Username string `json:"username"`
	Balance  float64
	Email    string `json:"email"`
}

// Регистрация пользователя
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка метода запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Чтение тела запроса
	decoder := json.NewDecoder(r.Body)
	var req SignupRequest
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Обработка запроса (здесь должен быть ваш код для регистрации пользователя)
	err = AddUser(req.Username, req.Password, req.Email)
	if err != nil {
		if strings.Contains(err.Error(), "уже зарегистрирован") {
			if strings.Contains(err.Error(), "email") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("emailDuplicated"))
				log.Printf("Email уже зарегистрирован")
			} else if strings.Contains(err.Error(), "username") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("usernameDuplicated"))
				log.Printf("Username уже зарегистрирован")
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Генерация access и refresh токенов
	accessClaims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Токен будет действительным в течение 24 часов
			Issuer:    "my_app",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshClaims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(), // Токен будет действительным в течение 7 дней
			Issuer:    "my_app",
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка ответа с токенами
	response := map[string]string{
		"accessToken":  accessString,
		"refreshToken": refreshString,
		"success":      "registerSuccess",
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка метода запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	// Инициализация соединения с базой данных
	DB := InitDB()

	// Чтение тела запроса
	decoder := json.NewDecoder(r.Body)
	var req LoginRequest
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Проверка логина и пароля
	if !CheckUserCredentials(DB, req.Username, req.Password) {
		http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
		return
	}

	// Получение информации о пользователе по имени пользователя
	user, err := GetUserByUsername(req.Username)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	// Создание access и refresh токенов
	accessString, refreshString, err := CreateTokens(req.Username)
	if err != nil {
		http.Error(w, "Не удалось создать токены", http.StatusInternalServerError)
		return
	}

	// Создайте объект AuthResponse, который включает в себя информацию о пользователе
	response := AuthResponse{
		AccessToken:  accessString,
		RefreshToken: refreshString,
		User:         user, // Передача информации о пользователе в ответ
	}

	log.Printf("Пользователь %s авторизован", req.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func CreateTokens(username string) (string, string, error) {
	// Создание access токена
	accessClaims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "myApp",
			Subject:   "access",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", errors.New("unable to sign access token")
	}

	// Создание refresh токена
	refreshClaims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "myApp",
			Subject:   "refresh",
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", errors.New("unable to sign refresh token")
	}

	return accessString, refreshString, nil
}

// AuthHandler обрабатывает запрос на обновление access токена
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка метода запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}
	// Чтение refresh токена из тела запроса
	var req RefreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	refreshToken := req.RefreshToken

	// Проверка refresh токена
	claims := &Claims{}
	refresh, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "Неверный токен", http.StatusBadRequest)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	if !refresh.Valid {
		http.Error(w, "Неверный токен", http.StatusBadRequest)
		return
	}

	// Генерация нового access токена
	accessClaims := &Claims{
		Username: claims.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Токен будет действительным в течение 24 часов
			Issuer:    "my_app",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка ответа с новым access токеном
	response := map[string]string{
		"accessToken": accessString,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получение токена из заголовка
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Нет токена авторизации", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Проверка алгоритма подписи
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("неверный алгоритм подписи")
			}
			return jwtSecret, nil
		})

		if err != nil {
			http.Error(w, "Неверный токен авторизации", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Проход проверки токена
			log.Println(claims["username"])
			// Передача управления следующему обработчику
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Неверный токен авторизации", http.StatusUnauthorized)
			return
		}
	})
}

// GetUserInfo возвращает информацию о пользователе
func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	// Получение имени пользователя из токена
	tokenString := r.Header.Get("Authorization")
	token, _ := jwt.Parse(tokenString, nil)
	claims, _ := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	// Ищем пользователя по имени пользователя
	user, err := GetUserByUsername(username)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	// Преобразование объекта пользователя в формат JSON
	userJSON, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка заголовков и отправка ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(userJSON)
}

func initHandlers() {

	// Настраиваем политику CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:8080", "http://localhost:8081"}, // Разрешаем запросы только с этого домена
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},        // Разрешаем указанные методы
		AllowedHeaders: []string{"Content-Type", "Authorization"},                  // Разрешаем указанные заголовки
	})

	// Создаем обработчик маршрутов
	router := mux.NewRouter()

	// Добавляем маршруты
	router.HandleFunc("/api/auth/signup", SignupHandler).Methods("POST")
	router.HandleFunc("/api/auth/signin", SignInHandler).Methods("POST")
	router.HandleFunc("/api/auth/refreshtoken", AuthHandler).Methods("POST")
	router.HandleFunc("/api/protected/user", GetUserInfo).Methods("GET").Name("Protected").Handler(authMiddleware(http.HandlerFunc(GetUserInfo)))

	//Обработчики сделок
	router.HandleFunc("/api/deletetrade/{tradeId}", DeleteTradeHandler).Methods("DELETE")
	router.HandleFunc("/api/addtrade", AddTradeHandler).Methods("POST")
	router.HandleFunc("/api/gettrades/{userId}", GetTradesHandler).Methods("GET")
	router.HandleFunc("/api/getstat/{userId}", GetStatHandler).Methods("GET")
	router.HandleFunc("/api/getprofits/{userId}", GetTradeProfitsHandler).Methods("GET")
	router.HandleFunc("/api/updatestatus/{tradeId}", UpdateTradeStatusHandler).Methods("PUT")
	router.HandleFunc("/api/updatecomment/{tradeId}", UpdateTradeCommentHandler).Methods("PUT")
	router.HandleFunc("/api/updatecommission/{tradeId}", UpdateTradeCommissionHandler).Methods("PUT")
	router.HandleFunc("/api/updatepnl/{tradeId}", UpdateTradePNLHandler).Methods("PUT")
	router.HandleFunc("/api/getdepo/{tradeId}", GetInitialDepositHandler).Methods("GET")
	router.HandleFunc("/api/updatepnl/{tradeId}", GetTradesForLast30DaysHandler).Methods("GET")

	// Запускаем сервер на порту 8080 с поддержкой политики CORS
	log.Println("Сервер запущен на http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", c.Handler(router)))
}
