<html>
    <head>
        <title> My first Web </title>
        <?php
         $host = "localhost";
         $dbname = "s67160365";
         $username = "s67160365";
         $password = "Faad65PZ";
         $con = mysqli_connect($host, $username, $password, $dbname);

         if (!$con){
            die("Connection Failed".mysqli_connect_error());
         }
         else{
            echo "Connection Sucessful!";
         }

        ?>
    </head>
    <body bg color = "black">
        <center>
        Hello World !! This is Matthew Home Page !!
        <br>
        <img src="sybau-invincible.png">
        <br>
        <table>
            <tr>
                <td> Name </td>
                <td> Salary </td>
        </tr>
        <?php
            $sql = "Select * FROM employees WHERE 1";
            $query = mysqli_query($con, $sql);
            while($row = mysqli_fetch_array($query)){
        ?>
            <tr>
                <td> <?php echo $row["emp_name"]; ?> </td>
                <td> <?php echo $row["salary"]; ?> </td>
            </tr>

        <?php
            }
        ?>
        </table>
    </body>
</html>