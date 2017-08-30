package main

import (
	"fmt"
	"html/template"
	"net/http"
	"simplyst/config"

	"gopkg.in/mgo.v2/bson"

	uuid "github.com/satori/go.uuid"
)

type user struct {
	UserName string
	Password string
	First    string
	Last     string
}

var dbSessions = map[string]string{}

var tpl *template.Template

var usernames = []user{}

func init() {

	tpl = template.Must(template.ParseGlob("templates/*"))

}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)

}

func index(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	tpl.ExecuteTemplate(w, "index.html", u)

}
func userFromForm(r *http.Request) (*user, error) {
	user := &user{
		UserName: r.FormValue("username"),
		Password: r.FormValue("password"),
		First:    r.FormValue("firstname"),
		Last:     r.FormValue("lastname"),
	}
	return user, nil

}

func signup(w http.ResponseWriter, req *http.Request) {
	// process form submission
	if req.Method == http.MethodPost {
		user, err := userFromForm(req)

		if err != nil {
			fmt.Println(err)
		}

		// get form values
		/*	un := req.FormValue("username")
			p := req.FormValue("password")
			f := req.FormValue("firstname")
			l := req.FormValue("lastname")
		*/
		/*
			// username taken?
			if _, ok := dbUsers[un]; ok {
				http.Error(w, "Username already taken", http.StatusForbidden)
				return
			}
		*/
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
		http.SetCookie(w, c)
		//user.Sessionid = c.Value
		err = config.Userscollection.Insert(user)

		dbSessions[c.Value] = user.UserName
		err = config.Sessionscollection.Insert(dbSessions)

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

func getUser(w http.ResponseWriter, req *http.Request) user {
	// get cookie
	c, err := req.Cookie("session")
	if err != nil {
		sID := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}

	}
	http.SetCookie(w, c)

	// if the user exists already, get user
	var u user
	/*if un, ok := dbSessions[c.Value]; ok {
		u = dbUsers[un]
	}*/

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
