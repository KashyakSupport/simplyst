package main

import (
	"fmt"
	"html/template"
	"net/http"
	"simplyst/config"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

type session struct {
	Sessionid string
	UserName  string
}

type user struct {
	UserName string
	Password []byte
	First    string
	Last     string
}

//var dbSessions = map[string]string{}
var tpl *template.Template
var usernames = []user{}
var sessionUsernames = []session{}
var pwd func(r *http.Request)

//var sessions session
var userflag bool

func init() {

	tpl = template.Must(template.ParseGlob("templates/*"))

}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/forgot", forgot)
	http.HandleFunc("/FYP", forgetpassword)
	http.HandleFunc("/home", home)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)

}

func index(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/home", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", u)

}

func home(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)

		return
	}
	tpl.ExecuteTemplate(w, "home.html", nil)
}
func userFromForm(r *http.Request) (*user, error) {
	user := &user{
		UserName: r.FormValue("username"),
		//Password: r.FormValue("password"),
		First: r.FormValue("firstname"),
		Last:  r.FormValue("lastname"),
	}
	return user, nil

}

func signup(w http.ResponseWriter, req *http.Request) {
	var objsession session
	/*	if alreadyLoggedIn(req) {
			http.Redirect(w, req, "/", http.StatusSeeOther)
			return
		}
	*/
	// process form submission
	if req.Method == http.MethodPost {
		user, err := userFromForm(req)

		if err != nil {
			fmt.Println(err)
		}

		bs, err := bcrypt.GenerateFromPassword([]byte(req.FormValue("password")), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		// username taken?
		usernames, err := allUsers()
		un := req.FormValue("username")

		for _, username := range usernames {

			if username.UserName == un {
				http.Error(w, "Username already taken", http.StatusForbidden)

				return
			}

		}
		// create session
		sID := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		//http.SetCookie(w, c)
		//user.Sessionid = c.Value
		user.Password = bs
		err = config.Userscollection.Insert(user)

		objsession.UserName = user.UserName
		objsession.Sessionid = c.Value
		err = config.Sessionscollection.Insert(objsession)

		/*dbSessions[c.Value] = un */

		// store user in dbUsers
		//u := user{un, p, f, l}
		//dbUsers[un] = u

		// redirect
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "signup.html", nil)
}

func login(w http.ResponseWriter, req *http.Request) {

	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/home", http.StatusSeeOther)
		return
	}

	if req.Method == http.MethodPost {

		// is there a username?
		userflag = loginuser(req)

		if userflag {
			un := req.FormValue("username")
			sessions, err := allUserNameFromSession()

			if err != nil {
				fmt.Println("error from login function", err)
			}

			for _, session := range sessions {

				if session.UserName == un {

					c := &http.Cookie{
						Name:  "session",
						Value: session.Sessionid,
					}
					fmt.Println("Cookie value before Set", c)
					http.SetCookie(w, c)
					fmt.Println("Cookie value after Set", c)
					http.Redirect(w, req, "/home", http.StatusSeeOther)
					//tpl.ExecuteTemplate(w, "home.html", nil)
					return

				}

			}

			// get seesion Id From Sssiond DB

			/*	// create session
				sID := uuid.NewV4()
				c := &http.Cookie{
					Name:  "session",
					Value: sID.String(),
				}

				http.SetCookie(w, c)

				dbSessions[c.Value] = un
			*/
		}

	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func getUser(w http.ResponseWriter, req *http.Request) user {
	// get cookie
	/*c, err := req.Cookie("session")
	if err != nil {
		sID := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}

	}
	http.SetCookie(w, c)*/
	var u user
	/*var s session
	Sessionid := c.Value
	//var dbSessions = map[string]string{}
	//get session id
	// get username based on session id
	// get user details based on user name
	fmt.Println(" c.value Sessionscollection error from get user function", c.Value)
	//errr := config.Sessionscollection.Find(bson.M{}).All(&sessions)
	errr := config.Sessionscollection.Find(bson.M{"Sessionid": Sessionid}).One(&s)
	if errr != nil {
		fmt.Println(" errr Sessionscollection error from get user function", errr)
	}
	//un := dbSessions[c.Value]

		for _, dbsession := range sessions {
			if dbsession.Sessionid == c.Value {
				s = dbsession
				//return s
			}
		}
	errrr := config.Userscollection.Find(bson.M{"username": s.UserName}).One(&u)
	if errrr != nil {
		fmt.Println("errrr Userscollection error from get user function", errrr)
	}
	fmt.Println("getting session id from get user", un)
	fmt.Println("getting session id from get user", c)
	fmt.Println("getting session id from get user", c.Value)
	usernames, err := allUsers()

	if err != nil {
		fmt.Println("error from login function", err)
	}

	for _, username := range usernames {
		if username.UserName == un {
			u = username
			return u
		}
	}
	//_, ok := dbUsers[un]
	*/
	return u
}

func allUsers() ([]user, error) {
	//	us := []user{}
	err := config.Userscollection.Find(bson.M{}).All(&usernames)

	if err != nil {
		fmt.Println("error from allusers function", err)
		return nil, err
	}
	fmt.Println("values from allusers function", usernames)

	return usernames, nil
}
func loginuser(req *http.Request) bool {
	un := req.FormValue("username")
	p := req.FormValue("password")

	usernames, err := allUsers()

	if err != nil {
		fmt.Println("error from login function", err)
	}

	for _, username := range usernames {

		if username.UserName == un {
			userflag = true
			err := bcrypt.CompareHashAndPassword(username.Password, []byte(p))
			if err != nil {
				//	http.Error(w, "Username and/or password do not match", http.StatusForbidden)
				fmt.Println("error from loginuser function", err)
				return false
			}

			//return userflag
		}

	}
	return userflag
}

func allUserNameFromSession() ([]session, error) {

	err := config.Sessionscollection.Find(bson.M{}).All(&sessionUsernames)

	if err != nil {
		fmt.Println("error from allUserNameFromSession()", err)
		return nil, err
	}
	fmt.Println("values from allUserNameFromSession", sessionUsernames)

	return sessionUsernames, nil

}

func alreadyLoggedIn(req *http.Request) bool {

	c, err := req.Cookie("session")
	if err != nil {
		return false
	}

	// get Session id
	// Based Seesion Id Get UserName
	// Check Whaeteher user Existed or not

	sessions, err := allUserNameFromSession()

	if err != nil {
		fmt.Println("error from login function", err)
	}

	for _, session := range sessions {

		if session.Sessionid == c.Value {

			return true

		}

	}

	return false
}

func logout(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	c, _ := req.Cookie("session")
	// delete the session
	//delete(dbSessions, c.Value)
	// remove the cookie
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func forgetpassword(w http.ResponseWriter, req *http.Request) {
	un := req.FormValue("pwdusername")
	req.ParseForm()
	fmt.Println(req.Form)

	usernames, err := allUsers()

	for _, username := range usernames {
		if username.UserName == un {
			fmt.Println("error from loginuser function success", err)
			http.Redirect(w, req, "/forgot", http.StatusSeeOther)
		} else {

			fmt.Printf("We can’t find a username that matches what you entered. Verify that your username is an email address ")
		}

	}

	tpl.ExecuteTemplate(w, "password.html", nil)

}

func forgot(w http.ResponseWriter, req *http.Request) {
	np := req.FormValue("newpassword")
	rnp := req.FormValue("reenterpassword")

	if np == rnp {
		//user := req.Form["pwdusername"]
		colQuerier := bson.M{"password": np}

		bs1, err := bcrypt.GenerateFromPassword([]byte(np), bcrypt.MinCost)

		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		change := bson.M{"$set": bson.M{"password": bs1}}

		err = config.Userscollection.Update(colQuerier, change)
		//	config.Sessionscollection.Find(&user).Update(colQuerier, change)
		//	err := bcrypt.CompareHashAndPassword(bs1, []byte(np))
		if err != nil {
			//	http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			//fmt.Println("error from loginuser function", err)

		}

		//err := bcrypt.CompareHashAndPassword(user.password, []byte(np))

		//	fmt.Println("error from loginuser function", err)

	} else {
		fmt.Printf("passwords entered donot  matched")

	}

	tpl.ExecuteTemplate(w, "forgot.html", nil)
}
