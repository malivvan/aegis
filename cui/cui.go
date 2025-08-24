package cui

import "github.com/malivvan/cui"

func Execute(version, keyring string) error {
	app := cui.NewApplication()

	view := cui.NewFlex()
	text1 := cui.NewTextView()
	text1.SetText("aegis " + version)
	text1.SetTextAlign(cui.AlignLeft)
	text2 := cui.NewTextView()
	text2.SetText(keyring)
	text2.SetTextAlign(cui.AlignCenter)
	text3 := cui.NewTextView()
	text3.SetText("Press Ctrl+C to exit")
	text3.SetTextAlign(cui.AlignRight)
	view.SetDirection(cui.FlexColumn)
	view.AddItem(text1, 0, 1, false)
	view.AddItem(text2, 0, 1, false)
	view.AddItem(text3, 0, 1, false)
	app.SetRoot(view, true)

	app.SetRoot(view, true)
	return app.Run()
}
