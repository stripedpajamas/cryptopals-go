package challenge31

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

type TimedByte struct {
	t time.Duration
	b byte
}
type Job struct {
	filename  string
	index     int
	guessByte byte
	guess     []byte
}

var netClient = &http.Client{}

// Maximum value of a slice of TimedBytes
func Max(slice []TimedByte) (m TimedByte) {
	if len(slice) > 0 {
		m = slice[0]
	}
	for i := 1; i < len(slice); i++ {
		if slice[i].t > m.t {
			m = slice[i]
		}
	}
	return
}

func measureWorker(jobs <-chan Job, results chan<- TimedByte) {
	for j := range jobs {
		myGuess := make([]byte, 20)
		copy(myGuess, j.guess)

		// set the jth byte to our current guess (i)
		myGuess[j.index] = j.guessByte
		// make the hex sig
		signature := hex.EncodeToString(myGuess)
		// format the request string
		req := fmt.Sprintf("http://127.0.0.1:8000/test?file=%s&signature=%s", j.filename, signature)
		// start the timer
		before := time.Now()
		// make the request
		res, err := netClient.Get(req)
		if err != nil {
			panic(err)
		}
		if res.StatusCode == 200 {
			// handle the last byte (or getting lucky)
			results <- TimedByte{
				t: 9999999999,
				b: j.guessByte,
			}
			return
		} else if res.StatusCode == 500 {
			res.Body.Close()
			// populate our time table
			results <- TimedByte{
				t: time.Since(before),
				b: j.guessByte,
			}
		}
	}
}

func DiscoverValidMAC(filename string, verbose bool) []byte {
	tr := &http.Transport{
		MaxIdleConns:        255,
		MaxIdleConnsPerHost: 255,
	}
	netClient = &http.Client{Transport: tr}
	// a sha1 hash is 20 bytes long
	// start with all zeros
	guess := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	times := make([]TimedByte, 255)
	//done := false

	for j := 0; j < 20; j++ {
		jobs := make(chan Job, 255)
		results := make(chan TimedByte, 255)

		// make some workers (150)
		for w := 0; w < 100; w++ {
			go measureWorker(jobs, results)
		}

		for i := byte(0); i < 255; i++ {
			// send jobs to the workers
			jobs <- Job{
				filename:  filename,
				index:     j,
				guessByte: i,
				guess:     guess,
			}
		}
		close(jobs)

		// wait for the threads to finish
		for i := 0; i < 255; i++ {
			times[i] = <-results
		}

		// find the request that took the longest and update our guess
		guess[j] = Max(times).b
		if verbose {
			fmt.Printf("%x\n", guess)
		}

		// reset everything to zeros
		times = make([]TimedByte, 255)
	}

	return guess
}
