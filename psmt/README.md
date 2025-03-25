Code for the main logic of the project.

The resulting program runs the proposed protocol over the given data by explicitly doing all the server's computation.

### Preparation of the Database

The program requires three types of files: (NAME: name of the database)

- `NAME_prepared.csv` contains the identifier and labels.
- `NAME_answer.csv` contains the correct label.
- `NAME_params.bin` contains the parameters (weight, bias) of the database.

###### Database will be added soon.

### Usage

After building the project, you can run the program `main_psmt` through the following command line.

```
./main_psmt -DBPath <str> -DBName <str>
```

For example, if your database is placed in "./data/" and the name of the database is CCTFD, then the command becomes

```
./main_psmt -DBPath ./data/ -DBName CCTFD
```

###### Enjoy!
