# GUI

The GUI is responsible for:

* running scans
* showing results
* charts
* settings

Run:

```bash
python run_gui.py
```

# Files

* app.py: starts the app
* main_window.py: the four tabs
* pipeline.py: runs the scan
* data.py: reads the output files
* charts.py: draws the charts
* widgets.py: chart cards and tiles
* workers.py: background tasks
* settings_store.py: saves the settings
