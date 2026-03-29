#!/bin/bash
log_file="/home/analyst/output/analysis.log"
samples_dir="/home/analyst/samples"
output_dir="/home/analyst/output"

timestamp() {
    date --iso-8601=seconds
}

log() {
    echo "$(timestamp) : $1" >> "$log_file"
}

# Prompt for .exe filename
echo "Enter the .exe filename (e.g., EldenRingSaveCopy.exe):"
read -r exe_file
exe_path="$samples_dir/$exe_file"

# Verify file exists
if [ ! -f "$exe_path" ]; then
    log "Error: $exe_file not found in $samples_dir"
    echo "Error: $exe_file not found in $samples_dir"
    exit 1
fi

log "Starting analysis for $exe_file"
echo "Analyzing $exe_file..."

# Check and initialize Wine prefix
log "Checking Wine prefix"
if [ ! -f "/home/analyst/.wine/system.reg" ] || [ ! -f "/home/analyst/.wine/drive_c/windows/system32/comctl32.dll" ]; then
    log "Initializing Wine prefix"
    WINEDLLOVERRIDES="winemenubuilder.exe=d" winecfg >> "$log_file" 2>&1
    if [ $? -ne 0 ]; then
        log "Error: Wine prefix initialization failed"
        echo "Error: Wine prefix initialization failed"
        exit 1
    fi
fi

# Verify prefix
log "Verifying Wine prefix"
ls -l /home/analyst/.wine/*.reg >> "$log_file" 2>&1
ls -l /home/analyst/.wine/drive_c/windows/system32 | grep -E 'comctl32.dll|shell32.dll' >> "$log_file" 2>&1
df -h /home/analyst/.wine >> "$log_file" 2>&1
if [ ! -f "/home/analyst/.wine/drive_c/windows/system32/shell32.dll" ]; then
    log "Error: Wine prefix incomplete (missing DLLs)"
    echo "Error: Wine prefix incomplete"
    exit 1
fi

# Test execution
log "Testing $exe_file execution"
wine "$exe_path" >> "$log_file" 2>&1

# Dynamic analysis
log "Tracing $exe_file with strace"
strace -t -s 200 -e trace=execve,open,read,write,close,stat,fstat,chdir,mkdir,fork,wait4 -o "$output_dir/raw_trace.log" wine "$exe_path" > "$output_dir/wine_trace.txt" 2>&1
if [ $? -eq 0 ]; then
    log "Completed tracing, output saved to $output_dir/wine_trace.txt"
else
    log "Error: Tracing failed"
    echo "Error: Tracing failed"
fi

# Format trace
log "Formatting strace output"
cat << 'AWK' > /tmp/format_strace.awk
BEGIN {
    print "Timestamp | Syscall | Arguments | Return | Error"
    print "---------|---------|-----------|--------|-------"
    prev_syscall = ""
}
/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/ {
    time=$1;
    sub(/.*[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\ /, "", $0);
    syscall=$1;
    args=$0;
    sub(/^[a-z0-9_]+\(/, "", args);
    sub(/\)[ \t]*=[ \t]*/, "|", args);
    sub(/[ \t]*$/, "", args);
    split(args, arr, "|");
    args=arr[1]; result=arr[2];
    error="";
    if (result ~ /-1/) {
        error=$0;
        sub(/.*-1 /, "", error);
    }
    if (syscall == "readlink" && prev_syscall == "readlink") next;
    if (syscall ~ /^(execve|open|mmap|read|write|close|stat|fstat|chdir|mkdir|fork|wait4)/) {
        printf "%s | %s | %s | %s | %s\n", time, syscall, substr(args, 1, 100), result, error
    }
    prev_syscall = syscall;
}
AWK
awk -f /tmp/format_strace.awk "$output_dir/raw_trace.log" > "$output_dir/trace.log"
log "Formatted strace output to $output_dir/trace.log"
cat "$output_dir/trace.log" >> "$log_file"

# Static analysis
log "Running static analysis"
file "$exe_path" > "$output_dir/exe_file.txt" 2>&1
log "Identified $exe_file type, saved to $output_dir/exe_file.txt"
cat "$output_dir/exe_file.txt" >> "$log_file"

strings "$exe_path" > "$output_dir/exe_strings.txt" 2>&1
log "Extracted strings, saved to $output_dir/exe_strings.txt"

# Skip binwalk if not installed
if command -v binwalk >/dev/null 2>&1; then
    binwalk "$exe_path" > "$output_dir/exe_binwalk.txt" 2>&1
    log "Checked structure, saved to $output_dir/exe_binwalk.txt"
    cat "$output_dir/exe_binwalk.txt" >> "$log_file"
else
    log "binwalk not available, skipping structure analysis"
    echo "binwalk not available" > "$output_dir/exe_binwalk.txt"
fi

grep -i 'CreateProcess\|WriteFile\|InternetOpen' "$output_dir/exe_strings.txt" > "$output_dir/exe_apis.txt" 2>&1
log "Searched for APIs, saved to $output_dir/exe_apis.txt"
cat "$output_dir/exe_apis.txt" >> "$log_file"

# Finalize
log "Analysis complete for $exe_file"
echo "Analysis complete. Outputs in $output_dir:"
ls -l "$output_dir" | tee -a "$log_file"
echo "Check $output_dir/trace.log for syscall trace."