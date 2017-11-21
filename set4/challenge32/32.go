package challenge32

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/stripedpajamas/cryptopals/set4/challenge31"
)

var netClient = &http.Client{}

// Maximum value of a slice of TimedBytes
func Max(slice []challenge31.TimedByte) (m challenge31.TimedByte) {
	if len(slice) > 0 {
		m = slice[0]
	}
	for i := 1; i < len(slice); i++ {
		if slice[i].T > m.T {
			m = slice[i]
		}
	}
	return
}

func measureWorker(jobs <-chan challenge31.Job, results chan<- challenge31.TimedByte) {
	for j := range jobs {
		myGuess := make([]byte, 20)
		copy(myGuess, j.Guess)

		// set the jth byte to our current guess (i)
		myGuess[j.Index] = j.GuessByte
		// make the hex sig
		signature := hex.EncodeToString(myGuess)
		// format the request string
		req := fmt.Sprintf("http://127.0.0.1:8000/test?file=%s&signature=%s", j.Filename, signature)

		// run many requests and take the average (nope. not good.)
		// take the smallest time and use that
		var average time.Duration
		for run := 0; run < 10; run++ {
			// start the timer
			before := time.Now()
			// make the request
			res, err := netClient.Get(req)
			if err != nil {
				panic(err)
			}
			if res.StatusCode == 200 {
				// handle the last byte (or getting lucky)
				results <- challenge31.TimedByte{
					T: 9999999999,
					B: j.GuessByte,
				}
				res.Body.Close()
				return
			} else if res.StatusCode == 500 {
				res.Body.Close()
				// populate our time table
				average += time.Since(before)
			}
		}
		results <- challenge31.TimedByte{
			T: average / 10,
			B: j.GuessByte,
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
	times := make([]challenge31.TimedByte, 255)

	for j := 0; j < 20; j++ {
		jobs := make(chan challenge31.Job, 255)
		results := make(chan challenge31.TimedByte, 255)

		// make some workers
		for w := 0; w < 10; w++ {
			go measureWorker(jobs, results)
		}

		for i := byte(0); i < 255; i++ {
			// send jobs to the workers
			jobs <- challenge31.Job{
				Filename:  filename,
				Index:     j,
				GuessByte: i,
				Guess:     guess,
			}
		}
		close(jobs)

		// wait for the threads to finish
		for i := 0; i < 255; i++ {
			times[i] = <-results
		}

		// find the request that took the longest and update our guess
		guess[j] = Max(times).B
		if verbose {
			fmt.Printf("%x\n", guess)
		}

		// reset everything to zeros
		times = make([]challenge31.TimedByte, 255)
	}

	return guess
}
