import cpp

from Function f
where f.getName() = "strlen"
select f.getAFile().getBaseName(), f, "a function named strlen"