package framework

import (
	"flag"
	"log"
	"os"
	"testing"
)

// setUp is an adapter for MainEntry and NewFramework to share similar code.
func setUp() *Framework {
	fopts := &frameworkOpts{}
	fopts.addToFlagSet(flag.CommandLine)
	// controller-runtime registers the --kubeconfig flag in client config
	// package:
	// https://github.com/kubernetes-sigs/controller-runtime/blob/v0.5.2/pkg/client/config/config.go#L39
	//
	// If this flag is not registered, do so. Otherwise retrieve its value.
	kcFlag := flag.Lookup(KubeConfigFlag)
	if kcFlag == nil {
		flag.StringVar(&fopts.kubeconfigPath, KubeConfigFlag, "", "path to kubeconfig")
	}

	flag.Parse()

	if kcFlag != nil {
		fopts.kubeconfigPath = kcFlag.Value.String()
	}

	f, err := newFramework(fopts)
	if err != nil {
		log.Fatalf("Failed to create framework: %v", err)
	}
	return f
}

// MainEntry sets up a Framework, which contains clients for the tests to share when
// interacting with the cluster. The Framework is exposed as a global variable called Global.
// MainEntry does effectively the same thing as NewFramework without returning the actual
// Framework reference.
func MainEntry(m *testing.M) {
	f := setUp()
	Global = f

	exitCode, err := f.runM(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

// NewFramework sets up and returns a Framework, which contains clients for the tests to share when
// interacting with a cluster. This method is meant to supersede MainEntry so we don't have to rely
// on a global variable for sharing the Framework between tests or test code.
func NewFramework() *Framework {
	return setUp()
}
