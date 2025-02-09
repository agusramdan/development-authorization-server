FROM openjdk:11
VOLUME /tmp
ADD target/app.jar /app.jar
RUN bash -c 'touch /app.jar'
EXPOSE 9000
ENTRYPOINT ["java","-jar","/app.jar"]