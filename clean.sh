echo `ps aux | grep ZeroAccess | awk '{print $2}' | xargs sudo kill -9`
