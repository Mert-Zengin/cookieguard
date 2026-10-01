package enforce

import "os"

func currentPID() int { return os.Getpid() }
