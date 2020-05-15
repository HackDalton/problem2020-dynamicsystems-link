FROM hackdalton/c-build-base:0.1.0 AS build

WORKDIR /src

COPY ./build.sh ./handle.c ./handle.h ./main.c ./util.c ./util.h ./

RUN chmod +x ./build.sh
RUN ./build.sh

FROM alpine

COPY --from=build /src/dslserver ./

CMD ["./dslserver"]