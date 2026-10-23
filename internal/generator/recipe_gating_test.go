package generator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/naming"
	"github.com/stretchr/testify/require"
)

// TestRecipeIntentGatingGeneratesGuards proves that recipe (README "intent")
// tools cannot re-expose a command the endpoint-mirror walker would prune. The
// emitted intents.go must guard both registration and the handler with
// recipeTargetExposed, and that function — exercised against a synthetic command
// tree in the generated package — must withhold a recipe whose target is hidden
// (itself or an ancestor, Cobra-hidden or mcp:hidden) and, under the MCP
// read-only switch, any target not annotated mcp:read-only / mcp:local-write.
func TestRecipeIntentGatingGeneratesGuards(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("recipegating")
	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	gen := New(apiSpec, outputDir)
	gen.VisionSet = VisionTemplateSet{MCP: true}
	gen.Narrative = &ReadmeNarrative{
		Recipes: []Recipe{
			{
				Title:       "Rank with numeric limit",
				Command:     "recipegating-pp-cli items rank --limit=5 --json",
				Explanation: "Rank items with a bounded result count.",
			},
		},
	}
	require.NoError(t, gen.Generate())

	intents := readGeneratedFile(t, outputDir, "internal", "mcp", "intents.go")
	require.Contains(t, intents, "func recipeTargetExposed(")
	require.Contains(t, intents, "if recipeTargetExposed(recipePath)")
	// The handler refuses at call time too, so a read-only switch flipped after
	// startup still blocks the recipe.
	require.Contains(t, intents, "tool is not available")

	modulePath := generatedModulePath(t, outputDir)

	runtimeTest := fmt.Sprintf(`package mcp

import (
	"testing"

	"github.com/spf13/cobra"

	"%s/internal/cliutil"
)

func newRecipeGatingTree() *cobra.Command {
	root := &cobra.Command{Use: "cli"}
	root.AddCommand(&cobra.Command{Use: "visible"})
	root.AddCommand(&cobra.Command{Use: "secret", Hidden: true})
	root.AddCommand(&cobra.Command{Use: "annhidden", Annotations: map[string]string{"mcp:hidden": "true"}})
	root.AddCommand(&cobra.Command{Use: "ro", Annotations: map[string]string{"mcp:read-only": "true"}})
	root.AddCommand(&cobra.Command{Use: "lw", Annotations: map[string]string{"mcp:local-write": "true"}})
	grp := &cobra.Command{Use: "grp", Hidden: true}
	grp.AddCommand(&cobra.Command{Use: "child"})
	root.AddCommand(grp)
	return root
}

func TestRecipeTargetExposed_GatesHiddenAndReadOnly(t *testing.T) {
	saved := recipeCommandRoot
	t.Cleanup(func() { recipeCommandRoot = saved })
	tree := newRecipeGatingTree()
	recipeCommandRoot = func() *cobra.Command { return tree }

	check := func(name string, path []string, want bool) {
		t.Helper()
		if got := recipeTargetExposed(path); got != want {
			t.Fatalf("%%s: recipeTargetExposed(%%v) = %%v, want %%v", name, path, got, want)
		}
	}

	// Read-only switch off: a hidden target (itself or via a hidden ancestor) is
	// withheld; everything else is exposed, including a target that does not
	// resolve to an in-tree command (it cannot be the hidden command).
	check("visible", []string{"visible"}, true)
	check("secret-hidden", []string{"secret"}, false)
	check("mcp-hidden", []string{"annhidden"}, false)
	check("hidden-ancestor", []string{"grp", "child"}, false)
	check("read-only-annotated", []string{"ro"}, true)
	check("local-write-annotated", []string{"lw"}, true)
	check("unresolved-target", []string{"does-not-exist"}, true)

	// Read-only switch on: only mcp:read-only / mcp:local-write targets survive;
	// a normal command, a hidden command, or an unverifiable (unresolved) target
	// is withheld.
	t.Setenv(cliutil.MCPReadOnlyEnvVar, "1")
	check("ro-under-readonly", []string{"ro"}, true)
	check("lw-under-readonly", []string{"lw"}, true)
	check("visible-under-readonly", []string{"visible"}, false)
	check("hidden-under-readonly", []string{"secret"}, false)
	check("unresolved-under-readonly", []string{"does-not-exist"}, false)
}
`, modulePath)

	require.NoError(t, os.WriteFile(
		filepath.Join(outputDir, "internal", "mcp", "recipe_gating_runtime_test.go"),
		[]byte(runtimeTest), 0o600))
	runGoCommand(t, outputDir, "mod", "tidy")
	runGoCommandRequired(t, outputDir, "test", "./internal/mcp", "-run", "^TestRecipeTargetExposed_", "-count=1")
}
