### Code for the main logic of the project.

The resulting program runs the proposed protocol over the given data from actual real-world databases.

### Preparation of the Database

The program requires three types of files: (NAME: name of the database)

- `NAME_prepared.csv` contains the identifier and labels.
- `NAME_answer.csv` contains the correct label.
- `NAME_params.bin` contains the parameters (weight, bias) of the database.

###### Database will be added soon.

### Usage

After building the project, you can run the program `main_psmt` through the following command line.

```
./main_psmt -DBPath <str> -DBName <str> -isSim <int> -isCompact <int> -scalingModSize <int> -numChunks <int>
```

Here, `-isSim`, `-isCompact`, `-scalingModSize` `-numChunks` denotes the following setting. 

- `-isSim`: Decide to simulate the results from other servers or not. If 0, then it computes all the operations for all the participated servers. Default is 1.
- `-isCompact`: Decide to use a compressed representation of the labels. This reduces the cost for logistic regression. This feature is enabled when `-isCompact=1`. Default is 1.
- `scalingModSize`: Sets the scaling mod size used for CKKS. Use 44 for this flag. This is the optimum value we found empirically for maximum accuracy.
- `-numChunks`: Set the number of ID ciphertexts held by each sender (horizontal segmentation of the database). This feature is disabled when `-numChunks=0`. Default is 0.

For example, if your database is placed in "./data/" and the name of the database is CCTFD, then the command becomes

```
./main_psmt -DBPath ./data/ -DBName CCTFD -isSim 1 -isCompact 1 -scalingModSize 44 -numChunks 0
```

###### Enjoy!
