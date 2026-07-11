# ClusterFuzzLite build image — OpenSSF Scorecard detects fuzzing via this file.
# Uses the OSS-Fuzz JavaScript base builder (Jazzer.js), which provides
# `compile_javascript_fuzzer`. See build.sh for the fuzz targets.
FROM gcr.io/oss-fuzz-base/base-builder-javascript
COPY . $SRC/redstamp
WORKDIR $SRC/redstamp
COPY .clusterfuzzlite/build.sh $SRC/build.sh
