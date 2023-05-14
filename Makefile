client:
	g++ client.cpp requests.cpp helpers.cpp buffer.cpp -o client
	
run:
	./client

clean:
	rm client