#!/bin/bash

###############################################
#  V1.0
#  28/04/2025
#  Yet Another macOS Forensics Collection Script
#  Based on SHOWMETHLOGS, but with more bite.
#  Can be run from JAMF, add to a policy, and then scope to a "FORENSIC" group. 
#  Step One - You need to add Terminal to "Full Disk Access", after the collection, TURN IT OFF AFTER THATS COMPLETED. 
#  Step Two - Run the script with "sudo ./yamfcs.sh 
#	- for "grab" to work add "--grab" and follow with the directory or file path. 
###############################################

# Define paths
temp_logs_folder="/tmp/logs"
desktop_path="$HOME/Desktop"
host=$(hostname)
loggedInUser=$(stat -f%Su /dev/console)
timestamp=$(date "+%H%M%S")
macOS=$(sw_vers -productVersion)
serial_number="$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')"

#Functions. 

function write_log() {
    local log="$temp_logs_folder/script_log.log"
    local log_data="$1"
    local log_entry="--- DATE: $timestamp: $log_data "
    echo "$log_entry" >> "$log"
}

function set_up(){
    mkdir -p "$temp_logs_folder"
	touch 	 "$temp_logs_folder/script_log.log"
	mkdir -p "$temp_logs_folder/browser"
	mkdir -p "$temp_logs_folder/logs"
	mkdir -p "$temp_logs_folder/shellhistory"
	mkdir -p "$temp_logs_folder/systemprofile"
	mkdir -p "$temp_logs_folder/tcc"
	mkdir -p "$temp_logs_folder/live_collection"
	mkdir -p "$temp_logs_folder/sysdiagnose"
}

# Version 2023.7.24-1 - Copyright (c) 2023 Pico Mitchell - MIT License - Full license and help info at https://randomapplications.com/json_extract
function json_extract() { 
	
	{ set -- "$(/usr/bin/osascript -l JavaScript -e 'ObjC.import("unistd");var run=argv=>{const args=[];let p;argv.forEach(a=>{if(!p&&/^-[^-]/.test(a)){a=a.split("").slice(1);for(const i in a){args.push("-"+a[i' \
	-e ']);if(/[ieE]/.test(a[i])){a.length>+i+1?args.push(a.splice(+i+(a[+i+1]==="="?2:1)).join("")):p=1;break}}}else{args.push(a);p=0}});let o,lA;for(const i in args){if(args[i]==="-i"&&!/^-[eE]$/.test(lA)){o=' \
	-e 'args.splice(+i,2)[1];break}lA=args[i]}const fH=$.NSFileHandle,hWS="fileHandleWithStandard",rtS="respondsToSelector";if(!o||o==="-"){const rdEOF="readDataToEndOfFile",aRE="AndReturnError";const h=fH[hWS+' \
	-e '"Input"];o=$.isatty(0)?"":$.NSString.alloc.initWithDataEncoding(h[rtS](rdEOF+aRE+":")?h[rdEOF+aRE](ObjC.wrap()):h[rdEOF],4).js.replace(/\n$/,"")}if($.NSFileManager.defaultManager.fileExistsAtPath(o))o=$' \
	-e '.NSString.stringWithContentsOfFileEncodingError(o,4,ObjC.wrap()).js;if(/^\s*[{[]/.test(o))o=JSON.parse(o);let e,eE,oL,o0,oT,oTS;const strOf=(O,N)=>typeof O==="object"?JSON.stringify(O,null,N):(O=O["to"+' \
	-e '"String"](),oT&&(O=O.trim()),oTS&&(O=O.replace(/\s+/g," ")),O),ext=(O,K)=>Array.isArray(O)?/^-?\d+$/.test(K)?(K=+K,O[K<0?O.length+K:K]):void 0:O instanceof Object?O[K]:void 0,ar="array",dc="dictionary"' \
	-e ',iv="Invalid option",naV="non-"+ar+" value";if(o||args.length){args.forEach(a=>{const isA=Array.isArray(o);if(e){o=ext(o,a);if(o===void 0)throw(isA?"Index":"Key")+" not found in "+(isA?ar:dc)+": "+a;e=' \
	-e '0}else if(eE){o=o.map(E=>(E=ext(E,a),E===void 0?null:E));eE=0}else if(a==="-l")oL=1;else if(a==="-0")o0=1;else if(a==="-t")oT=1;else if(a==="-T")oT=oTS=1;else{const isO=o instanceof Object;if(isO&&a===' \
	-e '"-e")e=1;else if(isA&&a==="-E")eE=1;else if(isA&&a==="-N")o=o.filter(E=>E!==null);else if(isO&&a==="-S")while(o instanceof Object&&Object.keys(o).length===1)o=o[Object.keys(o)[0]];else if(isA&&a==="-f"' \
	-e '&&typeof o.flat==="function")o=o.flat(Infinity);else if(isA&&a==="-s")o.sort((X,Y)=>strOf(X).localeCompare(strOf(Y)));else if(isA&&a==="-u")o=o.filter((E,I,A)=>A.indexOf(E)===I);else if(isO&&/^-[ckv]$/.' \
	-e 'test(a))o=a==="-c"?Object.keys(o).length:a==="-k"?Object.keys(o):Object.values(o);else if(/^-[eSckv]$/.test(a))throw iv+" for non-"+dc+" or "+naV+": "+a;else if(/^-[ENfsu]$/.test(a))throw iv+" for "+naV' \
	-e '+": "+a;else throw iv+": "+a}});const d=o0?"\0":"\n";o=((oL||o0)&&Array.isArray(o)?o.map(E=>strOf(E)).join(d):strOf(o,2))+d}o=ObjC.wrap(o).dataUsingEncoding(4);const h=fH[hWS+"Output"],wD="writeData";h[' \
	-e 'rtS](wD+":error:")?h[wD+"Error"](o,ObjC.wrap()):h[wD](o)}' -- "$@" 2>&1 >&3)"; } 3>&1; [ "${1##* }" != '(-2700)' ] || { set -- "json_extract ERROR${1#*Error}"; >&2 printf '%s\n' "${1% *}"; false; }
}

function grab_path() {
    local target_path="$1"
    local grab_dir="$temp_logs_folder/live_collection"

    mkdir -p "$grab_dir"

    if [[ -e "$target_path" ]]; then
        local base_name
        base_name=$(basename "$target_path")

        echo "Copying $target_path to $grab_dir/$base_name..."

        if [[ -d "$target_path" ]]; then
            cp -R "$target_path" "$grab_dir/$base_name"
        elif [[ -f "$target_path" ]]; then
            cp "$target_path" "$grab_dir/$base_name"
        else
            echo "Unsupported file type: $target_path"
            return 1
        fi

        echo "Copy complete!"
    else
        echo "Error: $target_path does not exist."
        return 1
    fi
}

function compress_logs () {
	
	local zip_filename="TMFDCT_${host}_${timestamp}.zip"

	zip -r "$desktop_path/$zip_filename" "$temp_logs_folder"

	if [[ -f "$desktop_path/$zip_filename" && -d "$temp_logs_folder" ]]; then
		write_log "log compression cleared, deleting temp logs"
		rm -r "$temp_logs_folder"
		exit 0
	else 
		echo "something went wrong, copy $temp_logs_folder manualy"
		exit 1
	fi
}

function browser_safari() {
	local CASE_DIR="$temp_logs_folder/browser/safari"
	local timestamp=$(date "+%H%M%S")
	mkdir -p "$CASE_DIR"

	for user_home in /Users/*; do
		[[ "$user_home" == "/Users/Shared" ]] && continue

		local username=$(basename "$user_home")
		local HISTORY_DB="$user_home/Library/Safari/History.db"
		local BOOKMARKS_PLIST="$user_home/Library/Safari/Bookmarks.plist"
		local DOWNLOADS_PLIST="$user_home/Library/Safari/Downloads.plist"
		local NOTIFICATIONS_PLIST="$user_home/Library/Safari/UserNotificationPermissions.plist"

		# Safari history
		if [[ -f "$HISTORY_DB" ]]; then
			local HISTORY_OUTPUT="$CASE_DIR/history_output_${username}_${timestamp}.csv"
			cp "$HISTORY_DB" "$CASE_DIR/history_${username}.db"
			echo "timestamp,url" > "$HISTORY_OUTPUT"
			sqlite3 "$HISTORY_DB" \
				"SELECT datetime(h.visit_time + 978307200, 'unixepoch'), i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id;" \
				>> "$HISTORY_OUTPUT"
		fi

		# Bookmarks
		if [[ -f "$BOOKMARKS_PLIST" ]]; then
			cp "$BOOKMARKS_PLIST" "$CASE_DIR/Bookmarks_${username}.plist"
		fi

		# Downloads
		if [[ -f "$DOWNLOADS_PLIST" ]]; then
			cp "$DOWNLOADS_PLIST" "$CASE_DIR/Downloads_${username}.plist"
		fi

		# Notification permissions
		if [[ -f "$NOTIFICATIONS_PLIST" ]]; then
			cp "$NOTIFICATIONS_PLIST" "$CASE_DIR/UserNotificationPermissions_${username}.plist"
		fi
	done
}

function browser_chrome() {
	local CASE_DIR="$temp_logs_folder/browser/chrome"
	local timestamp=$(date "+%H%M%S")
	local profile_name="Default"
	local chromedb="/Users/$loggedInUser/Library/Application Support/Google/Chrome/Default/History"
	local cookiesdb="/Users/$loggedInUser/Library/Application Support/Google/Chrome/Default/Cookies"
	local preferences="/Users/$loggedInUser/Library/Application Support/Google/Chrome/Default/Preferences"
	local extensions="/Users/$loggedInUser/Library/Application Support/Google/Chrome/Default/Extensions"
	local output_csv="$CASE_DIR/history_${loggedInUser}_${profile_name}_${timestamp}.csv"
	local output_csv2="$CASE_DIR/downloads_${loggedInUser}_${profile_name}_${timestamp}.csv"
	local output_csv3="$CASE_DIR/cookies_${loggedInUser}_${profile_name}_${timestamp}.csv"
	local output_csv4="$CASE_DIR/pref_${loggedInUser}_${profile_name}_${timestamp}.csv"
	local zip_filename="extensions_${loggedInUser}_${timestamp}.zip"
	mkdir -p "$CASE_DIR"

	#if we have a chromDB then lets copy it over
	if [[ -f "$chromedb" ]]; then 
	cp "$chromedb" "$CASE_DIR/history_$loggedInUser.db"

	# Export browser history
	echo "datetime,user,profile,url" > "$output_csv"
	sqlite3 "$CASE_DIR/history_$loggedInUser.db" \
		"SELECT datetime(((v.visit_time/1000000)-11644473600), 'unixepoch'), u.url FROM visits v INNER JOIN urls u ON u.id = v.url;" \
		| awk -v user="$loggedInUser" -v profile="$profile_name" -F'|' \
		'{ print $1 "," user "," profile "," $2 }' >> "$output_csv"

	# Export downloads
	echo "datetime,user,profile,url,target_path,danger_type,opened" > "$output_csv2"
	sqlite3 "$CASE_DIR/history_$loggedInUser.db" \
		"SELECT datetime(d.start_time/1000000 - 11644473600, 'unixepoch'), dc.url, d.target_path, d.danger_type, d.opened FROM downloads d INNER JOIN downloads_url_chains dc ON dc.id = d.id;" \
		| awk -v user="$loggedInUser" -v profile="$profile_name" -F'|' \
		'{ print $1 "," user "," profile "," $2 "," $3 "," $4 "," $5 }' >> "$output_csv2"

else
	echo "No Chrome DB"
fi

	# Get the cookies and export the data
	if [[ -f "$cookiesdb" ]]; then 
		cp "$cookiesdb" "$CASE_DIR/cookies_$loggedInUser.db"
		echo "datetime,user,profile,name,host_key,path,expires" > "$output_csv3"
		sqlite3 "$CASE_DIR/cookies_$loggedInUser.db" \
			"SELECT datetime(creation_utc/1000000 - 11644473600, 'unixepoch'), name, host_key, path, datetime(expires_utc/1000000 - 11644473600, 'unixepoch') FROM cookies;" \
			| awk -v user="$loggedInUser" -v profile="$profile_name" -F'|' \
			'{ print $1 "," user "," profile "," $2 "," $3 "," $4 "," $5 }' >> "$output_csv3"
		else 
			echo "cant find any chrome cookies"
		fi

	# Get the preferences and export them

	if [[ -f "$preferences" ]]; then
		cp "$preferences" "$CASE_DIR/preferences_${loggedInUser}_${profile_name}.json"
	else
		echo "No chrome prefs"
	fi

	# Get the extentions

	if [[ -d $extensions ]]; then
		zip -r "$CASE_DIR/$zip_filename" "$extensions"
	else
	 echo "no chrome extensions"
	fi 
}

function browser_firefox() {
	local CASE_DIR="$temp_logs_folder/browser/firefox"
	local timestamp=$(date "+%H%M%S")
	local profile_path="/Users/$loggedInUser/Library/Application Support/Firefox/Profiles"
	local output_csv="$CASE_DIR/history_${loggedInUser}_${timestamp}.csv"
	local output_csv2="$CASE_DIR/downloads_${loggedInUser}_${timestamp}.csv"
	mkdir -p "$CASE_DIR"
	

 #FF has multiple profiles even if a user only have one FF profile, so search through the directory and copy over any that we find
 	find "$profile_path" -type f \( -name "places.sqlite" -o -name "extensions.json" \) | while read -r file; do
		if [[ "$(basename "$file")" == "places.sqlite" ]]; then
		cp "$file" "$CASE_DIR/places_${loggedInUser}_${timestamp}.sqlite"
		echo "datetime,url" > "$output_csv"
		sqlite3 "$CASE_DIR/places_${loggedInUser}_${timestamp}.sqlite" \
				"SELECT datetime(hv.visit_date/1000000, 'unixepoch'), p.url FROM moz_historyvisits hv INNER JOIN moz_places p ON hv.place_id = p.id ORDER BY hv.visit_date;" \
				| awk -F'|' '{ print $1 "," $2 }' >> "$output_csv"
		echo "datetime,url,contents" > "$output_csv2"
			sqlite3 "$CASE_DIR/places_${loggedInUser}_${timestamp}.sqlite" \
				"SELECT datetime(moz_annos.dateAdded/1000000, 'unixepoch'), moz_places.url, moz_annos.content FROM moz_places JOIN moz_annos ON moz_places.id = moz_annos.place_id WHERE anno_attribute_id = 1;" \
				| awk -F'|' '{ print $1 "," $2 "," $3 }' >> "$output_csv2"
			fi
if [[ "$(basename "$file")" == "extensions.json" ]]; then
			cp "$file" "$CASE_DIR/extensions_${loggedInUser}_${timestamp}.json"
		fi
	done
			
}

function get_UnifiedLog() {
    local CASE_DIR="$temp_logs_folder/logs/unified_export"
    local logcmd="log show --info --backtrace --debug --loss --signpost --predicate"

    mkdir -p "$CASE_DIR"

    local filters=(
        "login:process == \"logind\""
        "tcc:process == \"tccd\""
        "ssh:process == \"sshd\""
        "failed_sudo:process == \"sudo\" and eventMessage CONTAINS \"TTY\" AND eventMessage CONTAINS \"3 incorrect password attempts\""
        "manual_configuration_profile_install:subsystem == \"com.apple.ManagedClient\" AND process == \"mdmclient\" AND category == \"MDMDaemon\" and eventMessage CONTAINS \"Installed configuration profile:\" AND eventMessage CONTAINS \"Source: Manual\""
        "screensharing:(process == \"screensharingd\" || process == \"ScreensharingAgent\")"
        "xprotect_remediator:subsystem == \"com.apple.XProtectFramework.PluginAPI\" && category == \"XPEvent.structured\""
    )

    for item in "${filters[@]}"; do
        local name="${item%%:*}"   # Text before colon
        local predicate="${item#*:}" # Text after colon

        echo "Collecting unified log for $name..."

        $logcmd "$predicate" > "$CASE_DIR/unified_${name}.txt" 2>/dev/null
    done
}



function collect_logs() {
	local CASE_DIR1="$temp_logs_folder/logs/sysmlibrarylogs"
	local CASE_DIR2="$temp_logs_folder/logs/userlibrarylogs"
	local CASE_DIR3="$temp_logs_folder/logs/varlogs"
	local CASE_DIR4="$temp_logs_folder/logs/auditlogs"
	local CASE_DIR5="$temp_logs_folder/logs/parsed_audit"

	mkdir -p "$CASE_DIR1" "$CASE_DIR2" "$CASE_DIR3" "$CASE_DIR4" "$CASE_DIR5"

	# Copy original log directories
	cp -r /Library/Logs "$CASE_DIR1"
	cp -r "/Users/$loggedInUser/Library/Logs" "$CASE_DIR2"
	cp -r /var/log "$CASE_DIR3"
	cp -r /var/audit "$CASE_DIR4"

	# Parse each binary audit file
	for auditfile in /var/audit/*; do
		if [[ -f "$auditfile" ]]; then
			local filename=$(basename "$auditfile")
			# Convert to readable text
			praudit "$auditfile" > "$CASE_DIR5/${filename}.txt"
			# Optional: Convert to XML format
			# praudit -x "$auditfile" > "$CASE_DIR5/${filename}.xml"
		fi
	done
}

function shellhistory() {
	local CASE_DIR="$temp_logs_folder/shellhistory"
	local homeDir="/Users/$loggedInUser"
	local shellfiles=(".ssh" ".bash_history" ".bash_profile" ".bashrc" ".bash_logout" ".zsh_history" ".zshenv" ".zprofile" ".zshrc" ".zlogin" ".zlogout" ".sh_history" ".config/fish/config.fish")
	local globalFiles=("/etc/profile" "/etc/zshenv" "/etc/zprofile" "/etc/zshrc" "/etc/zlogin" "/etc/zlogout")
	
	for filename in "${shellfiles[@]}"; do
		local sourceFile="$homeDir/$filename"
		if [[ -f "$sourceFile" ]]; then
			local sanitizedName="${filename//\//}"  # remove slashes for safe filenames
			cp "$sourceFile" "$CASE_DIR/${loggedInUser}_$sanitizedName"
		fi
	done

	for file in "${globalFiles[@]}"; do
		if [[ -f "$file" ]]; then
			local filename=$(basename "$file")
			cp "$file" "$CASE_DIR/etc_$filename"
		fi
	done
}

function system_profile () {
	local CASE_DIR1="$temp_logs_folder/systemprofile/ssh"
	local CASE_DIR2="$temp_logs_folder/systemprofile/userSSH"
	local CASE_DIR3="$temp_logs_folder/systemprofile/sudo"
	local CASE_DIR4="$temp_logs_folder/systemprofile/networking"
	local CASE_DIR5="$temp_logs_folder/systemprofile/xprotect"
	local output1="$temp_logs_folder/systemprofile/system_information.txt"
	local output2="$temp_logs_folder/systemprofile/installed_apps.txt"
	local output3="$temp_logs_folder/systemprofile/running_apps.txt"
	local output4="$temp_logs_folder/systemprofile/interfaces.txt"
	local output5="$temp_logs_folder/systemprofile/environment_variables.txt"
	local output6="$temp_logs_folder/systemprofile/security_assesment.txt"
	local output7="$temp_logs_folder/systemprofile/users.txt"
	local xprotect_version=$(defaults read "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" Version 2>/dev/null)
	local mrt_version=$(defaults read "/System/Library/CoreServices/MRT.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
	local xremed_version=$(defaults read "/System/Library/CoreServices/XProtectRemediator.bundle/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
	local installed_plist="/Library/Receipts/InstallHistory.plist"
	local tmp_json="/tmp/install_history.json"
	local xprotectYARA="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
	local xprotectVersion="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/version.plist"

	mkdir -p "$CASE_DIR1" "$CASE_DIR2" "$CASE_DIR3" "$CASE_DIR4" "$CASE_DIR5"

	# ----- Collection Info about .ssh, sudo, and host/dns ----- #
	cp -r /etc/ssh "$CASE_DIR1"

	cp -r "/Users/$loggedInUser/.ssh" "$CASE_DIR2/ssh"

	cp /etc/sudoers "$CASE_DIR3"

	cp -r /etc/sudoers.d "$CASE_DIR3"

	cp /etc/hosts "$CASE_DIR4"

	cp /private/var/run/resolv.conf "$CASE_DIR4"
		# ----- END ----- #

		# ----- System Summary ----- #
	{
		echo "HostName: $host"
		echo "UserName: $loggedInUser"
		echo "System Version: $macOS"
		echo "XProtect Version: $xprotect_version"
		echo "XProtect Remediator Version: $xremed_version"
		echo "MRT Version: $mrt_version"
		echo -e "\n----------\n"
	} > "$output1"
		# ----- END ----- #
	
		# ----- Installed Apps with Hash ----- #
	echo "App Name, MD5 Hash" > "$output2"

	find /Applications -maxdepth 1 -name "*.app" | while read -r app_path; do
		app_name=$(basename "$app_path")

		# Generate a hash of the full app folder
		hash=$(tar -cf - "$app_path" 2>/dev/null | md5 2>/dev/null | awk '{ print $NF }')

		if [[ -n "$hash" ]]; then
			echo "$app_name, $hash" >> "$output2"
		else
			echo "$app_name, ERROR" >> "$output2"
		fi
	done
		
		{ echo ""
    	  echo "---------- Install History ----------"
    	  echo "ProcessName,Datetime,ContentType,DisplayName,DisplayVersion,PackageIdentifiers"
		} >> "$output2"

		plutil -convert json "$installed_plist" -o "$tmp_json" 2>/dev/null

		local count=$(json_extract -i "$tmp_json" -c)

	for ((i=0; i<count; i++)); do
		local process=$(json_extract -i "$tmp_json" -e "$i" -e "processName" 2>/dev/null || echo "unknown")
		local date=$(json_extract -i "$tmp_json" -e "$i" -e "date" 2>/dev/null || echo "unknown")
		local content=$(json_extract -i "$tmp_json" -e "$i" -e "contentType" 2>/dev/null || echo "unknown")
		local name=$(json_extract -i "$tmp_json" -e "$i" -e "displayName" 2>/dev/null || echo "unknown")
		local version=$(json_extract -i "$tmp_json" -e "$i" -e "displayVersion" 2>/dev/null || echo "unknown")
		local ids=$(json_extract -i "$tmp_json" -e "$i" -e "packageIdentifiers" -l 2>/dev/null | tr '\n' ';' || echo "unknown")

		echo "$process,$date,$content,$name,$version,$ids" >> "$output2"

		rm -f "$tmp_json"
	done

		# ----- END ----- #

		# ----- Running processes ----- #

		echo "PID,Executable Path,Notes" > "$output3"
		ps ax -o pid= -o comm= | while read -r pid path; do
		# Only include absolute paths (i.e., skip bash built-ins)
			if [[ "$path" == /* ]]; then
				local notes=""

			# Check for potentially suspicious locations
			if [[ "$path" == /tmp/* || "$path" == /private/tmp/* || "$path" == /private/var/* || "$path" == /Users/*/Library/* ]]; then
				notes="Executable located in a user or temporary directory - often used by malware."
			fi

			echo "$pid,$path,$notes" >> "$output3"
		fi
	done

	# ----- END ----- #
	# ----- Networking INFO ----- #
	echo "Interface,IP Address,MAC Address,Status" > "$output4"

	for interface in $(networksetup -listallhardwareports | awk '/Device/ { print $2 }'); do
		# Get IP address (skip loopback)
		ip=$(ipconfig getifaddr "$interface" 2>/dev/null || echo "N/A")
		[[ "$ip" == "127.0.0.1" ]] && ip="N/A"

		# Get MAC address
		mac=$(ifconfig "$interface" | awk '/ether/{print $2}' | head -n 1)
		[[ -z "$mac" ]] && mac="N/A"

		# Get status (active/up/down)
		status=$(ifconfig "$interface" | grep -q "status: active" && echo "active" || echo "inactive")

		echo "$interface,$ip,$mac,$status" >> "$output4"
	done
	# ----- END ----- #

	# ----- environment_variables----- #
	echo "Environment Variables:" > "$output5"
	env >> "$output5"
	# ----- END ----- #
	
	# ----- XprotextStuff ------ #
     cp "$xprotectYARA" "$CASE_DIR5"
     cp "$xprotectVersion" "$CASE_DIR5"
	# ----- END ----- #

	# ----- Security Assesment----- #
	{
		echo " ----- Security Assesment-----"
		echo "Gatekeeper Status: $(spctl --status)"
		echo "SIP Status: $(csrutil status)"
		echo "Screen Sharing: $(launchctl list com.apple.screensharing)"
		echo "Firewall Status [Enabled = 1, Disabled = 0]: $(defaults read /Library/Preferences/com.apple.alf globalstate)"
		echo "Airdrop Status: $(ifconfig awdl0 | awk '/status/{print $2}')"
		echo "Remote Login: $(systemsetup -getremotelogin)"
		echo "Network File Shares: $(nfsd status)"
		echo "I/O Statistics: $(iostat)"
		echo "Login History: $(last)"
	} >> "$output6"

	 echo "Users:" > "$output7"

	 dscl . -list /Users UniqueID | awk '$2 >= 500 && $2 < 60000 { print $1 }' | while read -r user; do
        user_home=$(dscl . -read /Users/"$user" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
        user_groups=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')

        echo "Username: $user" >> "$output7"
        echo "Home Directory: $user_home" >> "$output7"
        echo "Groups: $user_groups" >> "$output7"
        echo "" >> "$output7"
    done
}

function collect_tcc() {
	local CASE_DIR="$temp_logs_folder/tcc"
	local system_tcc="/Library/Application Support/com.apple.TCC/TCC.db"
	local user_tcc="/Users/$loggedInUser/Library/Application Support/com.apple.TCC/TCC.db"
	local output_csv1="$CASE_DIR/tcc_root.csv"
	local output_csv2="$CASE_DIR/tcc_$loggedInUser.csv"
	echo "db_source,service,client,auth_value,auth_reason,last_modified" > "$output_csv1"
	echo "db_source,service,client,auth_value,auth_reason,last_modified" > "$output_csv2"

	cp "$system_tcc" "$CASE_DIR/tcc_root.db"
	cp "$user_tcc" "$CASE_DIR/tcc_$loggedInUser.db"

	sqlite3 "$CASE_DIR/tcc_root.db" "SELECT service, client, auth_value, auth_reason, datetime(last_modified + strftime('%s','2001-01-01'), 'unixepoch') FROM access;" | awk -F'|' -v src="$db_source" '{ print src "," $1 "," $2 "," $3 "," $4 "," $5 }' >> "$output_csv1"
	sqlite3 "$CASE_DIR/tcc_$loggedInUser.db" "SELECT service, client, auth_value, auth_reason, datetime(last_modified + strftime('%s','2001-01-01'), 'unixepoch') FROM access;" | awk -F'|' -v src="$db_source" '{ print src "," $1 "," $2 "," $3 "," $4 "," $5 }' >> "$output_csv2"
}

function sdiagnose(){

sysdiagnose -f "$temp_logs_folder/sysdiagnose" -n -b

if [ -d ""$temp_logs_folder/sysdiagnose ] && [ -z "$(ls -A "$temp_logs_folder/sysdiagnose")" ]; then
  write_log "the $temp_logs_folder/sysdiagnose folder is empty, something has gone wrong." 
  write_log "Moving on, try manually running the sysdiagnose comand later" 
else
  write_log "sysdiagnose has worked, moving on"
fi
}

function system_quickref () {
	local jamf_version=$(jamf -version | grep -o 'version=.*' | awk -F '=' '{print $2}')
	local uptime=$(bootDate=$(sysctl -n kern.boottime | awk -F'[ ,]' '{print $4}'); calculateUptimeInDays() { local uptimeInSeconds=$1; local secondsInDay=86400; uptimeInDays=$((uptimeInSeconds / secondsInDay)); echo "$uptimeInDays"; }; uptime=$((currentDate - bootDate)); calculateUptimeInDays "$uptime")
	local MAC=$(networksetup -getmacaddress Wi-Fi | grep -Eo '([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})' )
	local current_ip=$(ifconfig | grep "inet " | grep -Fv 127.0.0.1 | awk '{print $2}' | tr '\n' ',')
	local UNAME_MACHINE="$(uname -m)"

	write_log "System Quick Look Overview:"
	write_log "Jamf Version: $jamf_version"
	write_log "MacOS Version: $macOS"
	write_log "Mac Serial Number: $serial_number"
	write_log "Hostname: $host"
	write_log "Chip: $UNAME_MACHINE"
	write_log "LoggedOn User: $loggedInUser"
	write_log "macOS Uptime: $uptime"
	write_log "MAC Address(s): $MAC"
	write_log "IP Info: $current_ip"

}

######### Function Collections ###########

function collect_browser() {

	browser_safari
	browser_chrome
	browser_firefox
}

function system_rc() {

	collect_logs
	get_UnifiedLog
	shellhistory
	system_profile
	collect_tcc
	sdiagnose
}

#The Script 

#Setup file structure

echo "This is an experamental test version of the script"
echo "This shoudl not be used in production"
echo "ctrl+C now... you have been warned"
echo "10 second sleep"

#sleep 10

echo "Running the test script now"

if [[ "$1" == "--grab" && -n "$2" ]]; then
    grab_path "$2"
fi

set_up

collect_logs

system_quickref

collect_browser

system_rc

compress_logs

echo "done"