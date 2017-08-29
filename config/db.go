package config

import (
	"fmt"

	"gopkg.in/mgo.v2"
)

// DB database
var DB *mgo.Database

// users Userscollection data table
var Userscollection *mgo.Collection

// secc Sessionscollection table
var Sessionscollection *mgo.Collection

func init() {
	// get a mongo sessions
	s, err := mgo.Dial("mongodb://kashyaksupport:kashyaksupport@ds151973.mlab.com:51973/simplystdatabase")

	if err != nil {
		panic(err)
	}
	if err = s.Ping(); err != nil {
		panic(err)
	}

	DB = s.DB("simplystdatabase")
	Userscollection = DB.C("users")
	Sessionscollection = DB.C("sessions")

	fmt.Println("You connected to your mongo database.")

}
