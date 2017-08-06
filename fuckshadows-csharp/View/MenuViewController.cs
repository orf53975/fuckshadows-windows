using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using Fuckshadows.Controller;
using Fuckshadows.Model;
using Fuckshadows.Properties;
using Fuckshadows.Util;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;
using System.Linq;
using System.Threading.Tasks;

namespace Fuckshadows.View
{
    public class MenuViewController
    {
        // yes this is just a menu view controller
        // when config form is closed, it moves away from RAM
        // and it should just do anything related to the config form

        private FuckshadowsController controller;
        private UpdateChecker updateChecker;

        private NotifyIcon _notifyIcon;
        private Bitmap _iconBaseBitmap;
        private Icon _iconBase, _iconIn, _iconOut, _iconBoth, _targetIcon;
        private ContextMenu _contextMenu1;

        private bool _isFirstRun;
        private bool _isStartupChecking;
        private MenuItem _enableItem;
        private MenuItem _modeItem;
        private MenuItem _autoStartupItem;
        private MenuItem _shareOverLanItem;
        private MenuItem _seperatorItem;
        private MenuItem _configItem;
        private MenuItem _serversItem;
        private MenuItem _globalModeItem;
        private MenuItem _pacModeItem;
        private MenuItem _localPacItem;
        private MenuItem _onlinePacItem;
        private MenuItem _editLocalPacItem;
        private MenuItem _updateFromGfwListItem;
        private MenuItem _editGfwUserRuleItem;
        private MenuItem _editOnlinePacItem;
        private MenuItem _secureLocalPacUrlToggleItem;
        private MenuItem _autoCheckUpdatesToggleItem;
        private MenuItem _checkPreReleaseToggleItem;
        private MenuItem _hotKeyItem;
        private MenuItem _verboseLoggingToggleItem;
        private ConfigForm _configForm;
        private LogForm _logForm;
        private HotkeySettingsForm _hotkeySettingsForm;
        private string _urlToOpen;

        public MenuViewController(FuckshadowsController controller)
        {
            this.controller = controller;

            LoadMenu();

            controller.EnableStatusChanged += controller_EnableStatusChanged;
            controller.ConfigChanged += controller_ConfigChanged;
            controller.PacFileReadyToOpen += controller_FileReadyToOpen;
            controller.UserRuleFileReadyToOpen += controller_FileReadyToOpen;
            controller.ShareOverLanStatusChanged += controller_ShareOverLANStatusChanged;
            controller.VerboseLoggingStatusChanged += controller_VerboseLoggingStatusChanged;
            controller.EnableGlobalChanged += controller_EnableGlobalChanged;
            controller.Errored += controller_Errored;
            controller.UpdatePacFromGfwListCompleted += controller_UpdatePACFromGFWListCompleted;
            controller.UpdatePacFromGfwListError += controller_UpdatePACFromGFWListError;

            _notifyIcon = new NotifyIcon();
            UpdateTrayIcon();
            _notifyIcon.Visible = true;
            _notifyIcon.ContextMenu = _contextMenu1;
            _notifyIcon.BalloonTipClicked += notifyIcon1_BalloonTipClicked;
            _notifyIcon.MouseClick += notifyIcon1_Click;
            _notifyIcon.MouseDoubleClick += notifyIcon1_DoubleClick;
            _notifyIcon.BalloonTipClosed += _notifyIcon_BalloonTipClosed;
            controller.TrafficChanged += controller_TrafficChanged;

            this.updateChecker = new UpdateChecker();
            updateChecker.CheckUpdateCompleted += updateChecker_CheckUpdateCompleted;

            LoadCurrentConfiguration();

            Configuration config = controller.GetConfigurationCopy();

            if (config.isDefault)
            {
                _isFirstRun = true;
                ShowConfigForm();
            }
            else if (config.autoCheckUpdate)
            {
                _isStartupChecking = true;
                updateChecker.CheckUpdate(config, 3000);
            }
        }

        private void controller_TrafficChanged(object sender, EventArgs e)
        {
            if (_iconBaseBitmap == null)
                return;

            Icon newIcon;

            bool hasInbound = controller.trafficPerSecondQueue.Last().inboundIncreasement > 0;
            bool hasOutbound = controller.trafficPerSecondQueue.Last().outboundIncreasement > 0;

            if (hasInbound && hasOutbound)
                newIcon = _iconBoth;
            else if (hasInbound)
                newIcon = _iconIn;
            else if (hasOutbound)
                newIcon = _iconOut;
            else
                newIcon = _iconBase;

            if (newIcon != _targetIcon)
            {
                _targetIcon = newIcon;
                _notifyIcon.Icon = newIcon;
            }
        }

        private void controller_Errored(object sender, System.IO.ErrorEventArgs e)
        {
            MessageBox.Show(e.GetException().ToString(),
                String.Format(I18N.GetString("Fuckshadows Error: {0}"), e.GetException().Message));
        }

        #region Tray Icon

        private void UpdateTrayIcon()
        {
            int dpi;
            Graphics graphics = Graphics.FromHwnd(IntPtr.Zero);
            dpi = (int) graphics.DpiX;
            graphics.Dispose();
            _iconBaseBitmap = null;
            if (dpi < 97)
            {
                // dpi = 96;
                _iconBaseBitmap = Resources.ss16;
            }
            else if (dpi < 121)
            {
                // dpi = 120;
                _iconBaseBitmap = Resources.ss20;
            }
            else
            {
                _iconBaseBitmap = Resources.ss24;
            }
            Configuration config = controller.GetConfigurationCopy();
            bool enabled = config.enabled;
            bool global = config.global;
            _iconBaseBitmap = getTrayIconByState(_iconBaseBitmap, enabled, global);

            _iconBase = Icon.FromHandle(_iconBaseBitmap.GetHicon());
            _targetIcon = _iconBase;
            _iconIn = Icon.FromHandle(AddBitmapOverlay(_iconBaseBitmap, Resources.ssIn24).GetHicon());
            _iconOut = Icon.FromHandle(AddBitmapOverlay(_iconBaseBitmap, Resources.ssOut24).GetHicon());
            _iconBoth =
                Icon.FromHandle(AddBitmapOverlay(_iconBaseBitmap, Resources.ssIn24, Resources.ssOut24).GetHicon());
            _notifyIcon.Icon = _targetIcon;

            string serverInfo = null;
            if (controller.GetCurrentStrategy() != null)
            {
                serverInfo = controller.GetCurrentStrategy().Name;
            }
            else
            {
                serverInfo = config.GetCurrentServer().FriendlyName();
            }
            // show more info by hacking the P/Invoke declaration for NOTIFYICONDATA inside Windows Forms
            string text = I18N.GetString("Fuckshadows") + " " + UpdateChecker.Version + "\n" +
                          (enabled
                              ? I18N.GetString("System Proxy On: ") +
                                (global ? I18N.GetString("Global") : I18N.GetString("PAC"))
                              : String.Format(I18N.GetString("Running: Port {0}"), config.localPort))
                          // this feedback is very important because they need to know Fuckshadows is running
                          + "\n" + serverInfo;
            ViewUtils.SetNotifyIconText(_notifyIcon, text);
        }

        private Bitmap getTrayIconByState(Bitmap originIcon, bool enabled, bool global)
        {
            Bitmap iconCopy = new Bitmap(originIcon);
            for (int x = 0; x < iconCopy.Width; x++)
            {
                for (int y = 0; y < iconCopy.Height; y++)
                {
                    Color color = originIcon.GetPixel(x, y);
                    if (color.A != 0)
                    {
                        if (!enabled)
                        {
                            Color flyBlue = Color.FromArgb(192, 192, 192);
                            // Multiply with flyBlue
                            int red = color.R * flyBlue.R / 255;
                            int green = color.G * flyBlue.G / 255;
                            int blue = color.B * flyBlue.B / 255;
                            iconCopy.SetPixel(x, y, Color.FromArgb(color.A, red, green, blue));
                        }
                        else if (global)
                        {
                            Color flyBlue = Color.FromArgb(25, 125, 191);
                            // Multiply with flyBlue
                            int red = color.R * flyBlue.R / 255;
                            int green = color.G * flyBlue.G / 255;
                            int blue = color.B * flyBlue.B / 255;
                            iconCopy.SetPixel(x, y, Color.FromArgb(color.A, red, green, blue));
                        }
                    }
                    else
                    {
                        iconCopy.SetPixel(x, y, Color.FromArgb(color.A, color.R, color.G, color.B));
                    }
                }
            }
            return iconCopy;
        }

        private Bitmap AddBitmapOverlay(Bitmap original, params Bitmap[] overlays)
        {
            Bitmap bitmap = new Bitmap(original.Width, original.Height, PixelFormat.Format64bppArgb);
            Graphics canvas = Graphics.FromImage(bitmap);
            canvas.DrawImage(original, new Point(0, 0));
            foreach (Bitmap overlay in overlays)
            {
                canvas.DrawImage(new Bitmap(overlay, original.Size), new Point(0, 0));
            }
            canvas.Save();
            return bitmap;
        }

        #endregion

        #region MenuItems and MenuGroups

        private MenuItem CreateMenuItem(string text, EventHandler click)
        {
            return new MenuItem(I18N.GetString(text), click);
        }

        private MenuItem CreateMenuGroup(string text, MenuItem[] items)
        {
            return new MenuItem(I18N.GetString(text), items);
        }

        private void LoadMenu()
        {
            this._contextMenu1 = new ContextMenu(new MenuItem[]
            {
                this._enableItem = CreateMenuItem("Enable System Proxy", new EventHandler(this.EnableItem_Click)),
                this._modeItem = CreateMenuGroup("Mode", new MenuItem[]
                {
                    this._pacModeItem = CreateMenuItem("PAC", new EventHandler(this.PACModeItem_Click)),
                    this._globalModeItem = CreateMenuItem("Global", new EventHandler(this.GlobalModeItem_Click))
                }),
                this._serversItem = CreateMenuGroup("Servers", new MenuItem[]
                {
                    this._seperatorItem = new MenuItem("-"),
                    this._configItem = CreateMenuItem("Edit Servers...", new EventHandler(this.Config_Click)),
                    CreateMenuItem("Statistics Config...", StatisticsConfigItem_Click),
                    new MenuItem("-"),
                    CreateMenuItem("Share Server Config...", new EventHandler(this.QRCodeItem_Click)),
                    CreateMenuItem("Scan QRCode from Screen...", new EventHandler(this.ScanQRCodeItem_Click)),
                    CreateMenuItem("Import URL from Clipboard...", new EventHandler(this.ImportURLItem_Click))
                }),
                CreateMenuGroup("PAC ", new MenuItem[]
                {
                    this._localPacItem = CreateMenuItem("Local PAC", new EventHandler(this.LocalPACItem_Click)),
                    this._onlinePacItem = CreateMenuItem("Online PAC", new EventHandler(this.OnlinePACItem_Click)),
                    new MenuItem("-"),
                    this._editLocalPacItem =
                        CreateMenuItem("Edit Local PAC File...", new EventHandler(this.EditPACFileItem_Click)),
                    this._updateFromGfwListItem =
                        CreateMenuItem("Update Local PAC from GFWList",
                            new EventHandler(this.UpdatePACFromGFWListItem_Click)),
                    this._editGfwUserRuleItem =
                        CreateMenuItem("Edit User Rule for GFWList...",
                            new EventHandler(this.EditUserRuleFileForGFWListItem_Click)),
                    this._secureLocalPacUrlToggleItem =
                        CreateMenuItem("Secure Local PAC", new EventHandler(this.SecureLocalPacUrlToggleItem_Click)),
                    CreateMenuItem("Copy Local PAC URL", new EventHandler(this.CopyLocalPacUrlItem_Click)),
                    this._editOnlinePacItem =
                        CreateMenuItem("Edit Online PAC URL...", new EventHandler(this.UpdateOnlinePACURLItem_Click)),
                }),
                new MenuItem("-"),
                this._autoStartupItem = CreateMenuItem("Start on Boot", new EventHandler(this.AutoStartupItem_Click)),
                this._shareOverLanItem =
                    CreateMenuItem("Allow Clients from LAN", new EventHandler(this.ShareOverLANItem_Click)),
                new MenuItem("-"),
                this._hotKeyItem = CreateMenuItem("Edit Hotkeys...", new EventHandler(this.hotKeyItem_Click)),
                CreateMenuItem("Show Logs...", new EventHandler(this.ShowLogItem_Click)),
                this._verboseLoggingToggleItem =
                    CreateMenuItem("Verbose Logging", new EventHandler(this.VerboseLoggingToggleItem_Click)),
                new MenuItem("-"),
                CreateMenuGroup("Updates...", new MenuItem[]
                {
                    CreateMenuItem("Check for Updates...", new EventHandler(this.checkUpdatesItem_Click)),
                    new MenuItem("-"),
                    this._autoCheckUpdatesToggleItem =
                        CreateMenuItem("Check for Updates at Startup",
                            new EventHandler(this.autoCheckUpdatesToggleItem_Click)),
                    this._checkPreReleaseToggleItem =
                        CreateMenuItem("Check Pre-release Version",
                            new EventHandler(this.checkPreReleaseToggleItem_Click)),
                }),
                CreateMenuItem("About...", new EventHandler(this.AboutItem_Click)),
                CreateMenuItem("Quit", new EventHandler(this.Quit_Click))
            });
        }

        #endregion

        private void controller_ConfigChanged(object sender, EventArgs e)
        {
            LoadCurrentConfiguration();
            UpdateTrayIcon();
        }

        private void controller_EnableStatusChanged(object sender, EventArgs e)
        {
            _enableItem.Checked = controller.GetConfigurationCopy().enabled;
            _modeItem.Enabled = _enableItem.Checked;
        }

        void controller_ShareOverLANStatusChanged(object sender, EventArgs e)
        {
            _shareOverLanItem.Checked = controller.GetConfigurationCopy().shareOverLan;
        }

        void controller_VerboseLoggingStatusChanged(object sender, EventArgs e)
        {
            _verboseLoggingToggleItem.Checked = controller.GetConfigurationCopy().isVerboseLogging;
        }

        void controller_EnableGlobalChanged(object sender, EventArgs e)
        {
            _globalModeItem.Checked = controller.GetConfigurationCopy().global;
            _pacModeItem.Checked = !_globalModeItem.Checked;
        }

        void controller_FileReadyToOpen(object sender, FuckshadowsController.PathEventArgs e)
        {
            string argument = @"/select, " + e.Path;

            System.Diagnostics.Process.Start("explorer.exe", argument);
        }

        void ShowBalloonTip(string title, string content, ToolTipIcon icon, int timeout)
        {
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = content;
            _notifyIcon.BalloonTipIcon = icon;
            _notifyIcon.ShowBalloonTip(timeout);
        }

        void controller_UpdatePACFromGFWListError(object sender, System.IO.ErrorEventArgs e)
        {
            ShowBalloonTip(I18N.GetString("Failed to update PAC file"), e.GetException().Message, ToolTipIcon.Error,
                5000);
            Logging.LogUsefulException(e.GetException());
        }

        void controller_UpdatePACFromGFWListCompleted(object sender, GFWListUpdater.ResultEventArgs e)
        {
            string result = e.Success
                ? I18N.GetString("PAC updated")
                : I18N.GetString("No updates found. Please report to GFWList if you have problems with it.");
            ShowBalloonTip(I18N.GetString("Fuckshadows"), result, ToolTipIcon.Info, 1000);
        }

        void updateChecker_CheckUpdateCompleted(object sender, EventArgs e)
        {
            if (updateChecker.NewVersionFound)
            {
                ShowBalloonTip(
                    String.Format(I18N.GetString("Fuckshadows {0} Update Found"),
                        updateChecker.LatestVersionNumber + updateChecker.LatestVersionSuffix),
                    I18N.GetString("Click here to update"), ToolTipIcon.Info, 5000);
            }
            else if (!_isStartupChecking)
            {
                ShowBalloonTip(I18N.GetString("Fuckshadows"), I18N.GetString("No update is available"), ToolTipIcon.Info,
                    5000);
            }
            _isStartupChecking = false;
        }

        void notifyIcon1_BalloonTipClicked(object sender, EventArgs e)
        {
            if (updateChecker.NewVersionFound)
            {
                updateChecker.NewVersionFound = false; /* Reset the flag */
                if (System.IO.File.Exists(updateChecker.LatestVersionLocalName))
                {
                    string argument = "/select, \"" + updateChecker.LatestVersionLocalName + "\"";
                    System.Diagnostics.Process.Start("explorer.exe", argument);
                }
            }
        }

        private void _notifyIcon_BalloonTipClosed(object sender, EventArgs e)
        {
            if (updateChecker.NewVersionFound)
            {
                updateChecker.NewVersionFound = false; /* Reset the flag */
            }
        }

        private void LoadCurrentConfiguration()
        {
            Configuration config = controller.GetConfigurationCopy();
            UpdateServersMenu();
            _enableItem.Checked = config.enabled;
            _modeItem.Enabled = config.enabled;
            _globalModeItem.Checked = config.global;
            _pacModeItem.Checked = !config.global;
            _shareOverLanItem.Checked = config.shareOverLan;
            _verboseLoggingToggleItem.Checked = config.isVerboseLogging;
            _autoStartupItem.Checked = AutoStartup.Check();
            _onlinePacItem.Checked = _onlinePacItem.Enabled && config.useOnlinePac;
            _localPacItem.Checked = !_onlinePacItem.Checked;
            _secureLocalPacUrlToggleItem.Checked = config.secureLocalPac;
            UpdatePacItemsEnabledStatus();
            UpdateUpdateMenu();
        }

        private void UpdateServersMenu()
        {
            var items = _serversItem.MenuItems;
            while (items[0] != _seperatorItem)
            {
                items.RemoveAt(0);
            }
            int i = 0;
            foreach (var strategy in controller.GetStrategies())
            {
                MenuItem item = new MenuItem(strategy.Name) {Tag = strategy.ID};
                item.Click += AStrategyItem_Click;
                items.Add(i, item);
                i++;
            }

            // user wants a seperator item between strategy and servers menugroup
            items.Add(i++, new MenuItem("-"));

            int strategyCount = i;
            Configuration configuration = controller.GetConfigurationCopy();
            foreach (var server in configuration.configs)
            {
                MenuItem item = new MenuItem(server.FriendlyName()) {Tag = i - strategyCount};
                item.Click += AServerItem_Click;
                items.Add(i, item);
                i++;
            }

            foreach (MenuItem item in items)
            {
                if (item.Tag != null &&
                    (item.Tag.ToString() == configuration.index.ToString() ||
                     item.Tag.ToString() == configuration.strategy))
                {
                    item.Checked = true;
                }
            }
        }

        private void ShowConfigForm()
        {
            if (_configForm != null)
            {
                _configForm.Activate();
            }
            else
            {
                _configForm = new ConfigForm(controller);
                _configForm.Show();
                _configForm.Activate();
                _configForm.FormClosed += configForm_FormClosed;
            }
        }

        private void ShowHotKeySettingsForm()
        {
            if (_hotkeySettingsForm != null)
            {
                _hotkeySettingsForm.Activate();
            }
            else
            {
                _hotkeySettingsForm = new HotkeySettingsForm(controller);
                _hotkeySettingsForm.Show();
                _hotkeySettingsForm.Activate();
                _hotkeySettingsForm.FormClosed += hotkeySettingsForm_FormClosed;
            }
        }

        private void ShowLogForm()
        {
            if (_logForm != null)
            {
                _logForm.Activate();
            }
            else
            {
                _logForm = new LogForm(controller, Logging.LogFilePath);
                _logForm.Show();
                _logForm.Activate();
                _logForm.FormClosed += logForm_FormClosed;
            }
        }

        void logForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            _logForm.Dispose();
            _logForm = null;
        }

        void configForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            _configForm.Dispose();
            _configForm = null;
            if (_isFirstRun)
            {
                CheckUpdateForFirstRun();
                ShowFirstTimeBalloon();
                _isFirstRun = false;
            }
        }

        void hotkeySettingsForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            _hotkeySettingsForm.Dispose();
            _hotkeySettingsForm = null;
        }

        private void Config_Click(object sender, EventArgs e)
        {
            ShowConfigForm();
        }

        private void Quit_Click(object sender, EventArgs e)
        {
            controller.Stop();
            _notifyIcon.Visible = false;
            Application.Exit();
        }

        private void CheckUpdateForFirstRun()
        {
            Configuration config = controller.GetConfigurationCopy();
            if (config.isDefault) return;
            _isStartupChecking = true;
            updateChecker.CheckUpdate(config, 3000);
        }

        private void ShowFirstTimeBalloon()
        {
            _notifyIcon.BalloonTipTitle = I18N.GetString("Fuckshadows is here");
            _notifyIcon.BalloonTipText = I18N.GetString("You can turn on/off Fuckshadows in the context menu");
            _notifyIcon.BalloonTipIcon = ToolTipIcon.Info;
            _notifyIcon.ShowBalloonTip(0);
        }

        private void AboutItem_Click(object sender, EventArgs e)
        {
            Process.Start("https://github.com/Fuckshadows/Fuckshadows-windows");
        }

        private void notifyIcon1_Click(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Middle)
            {
                ShowLogForm();
            }
        }

        private void notifyIcon1_DoubleClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowConfigForm();
            }
        }

        private void EnableItem_Click(object sender, EventArgs e)
        {
            controller.ToggleEnable(!_enableItem.Checked);
        }

        private void GlobalModeItem_Click(object sender, EventArgs e)
        {
            controller.ToggleGlobal(true);
        }

        private void PACModeItem_Click(object sender, EventArgs e)
        {
            controller.ToggleGlobal(false);
        }

        private void ShareOverLANItem_Click(object sender, EventArgs e)
        {
            _shareOverLanItem.Checked = !_shareOverLanItem.Checked;
            controller.ToggleShareOverLAN(_shareOverLanItem.Checked);
        }

        private void EditPACFileItem_Click(object sender, EventArgs e)
        {
            controller.TouchPACFile();
        }

        private void UpdatePACFromGFWListItem_Click(object sender, EventArgs e)
        {
            controller.UpdatePACFromGFWList();
        }

        private void EditUserRuleFileForGFWListItem_Click(object sender, EventArgs e)
        {
            controller.TouchUserRuleFile();
        }

        private void AServerItem_Click(object sender, EventArgs e)
        {
            MenuItem item = (MenuItem) sender;
            controller.SelectServerIndex((int) item.Tag);
        }

        private void AStrategyItem_Click(object sender, EventArgs e)
        {
            MenuItem item = (MenuItem) sender;
            controller.SelectStrategy((string) item.Tag);
        }

        private void VerboseLoggingToggleItem_Click(object sender, EventArgs e)
        {
            _verboseLoggingToggleItem.Checked = !_verboseLoggingToggleItem.Checked;
            controller.ToggleVerboseLogging(_verboseLoggingToggleItem.Checked);
        }

        private void StatisticsConfigItem_Click(object sender, EventArgs e)
        {
            StatisticsStrategyConfigurationForm form = new StatisticsStrategyConfigurationForm(controller);
            form.Show();
        }

        private void QRCodeItem_Click(object sender, EventArgs e)
        {
            QRCodeForm qrCodeForm = new QRCodeForm(controller.GetQRCodeForCurrentServer());
            //qrCodeForm.Icon = this.Icon;
            // TODO
            qrCodeForm.Show();
        }

        private void ScanQRCodeItem_Click(object sender, EventArgs e)
        {
            foreach (Screen screen in Screen.AllScreens)
            {
                using (Bitmap fullImage = new Bitmap(screen.Bounds.Width,
                    screen.Bounds.Height))
                {
                    using (Graphics g = Graphics.FromImage(fullImage))
                    {
                        g.CopyFromScreen(screen.Bounds.X,
                            screen.Bounds.Y,
                            0, 0,
                            fullImage.Size,
                            CopyPixelOperation.SourceCopy);
                    }
                    int maxTry = 10;
                    for (int i = 0; i < maxTry; i++)
                    {
                        int marginLeft = (int) ((double) fullImage.Width * i / 2.5 / maxTry);
                        int marginTop = (int) ((double) fullImage.Height * i / 2.5 / maxTry);
                        Rectangle cropRect = new Rectangle(marginLeft, marginTop, fullImage.Width - marginLeft * 2,
                            fullImage.Height - marginTop * 2);
                        Bitmap target = new Bitmap(screen.Bounds.Width, screen.Bounds.Height);

                        double imageScale = (double) screen.Bounds.Width / (double) cropRect.Width;
                        using (Graphics g = Graphics.FromImage(target))
                        {
                            g.DrawImage(fullImage, new Rectangle(0, 0, target.Width, target.Height),
                                cropRect,
                                GraphicsUnit.Pixel);
                        }
                        var source = new BitmapLuminanceSource(target);
                        var bitmap = new BinaryBitmap(new HybridBinarizer(source));
                        QRCodeReader reader = new QRCodeReader();
                        var result = reader.decode(bitmap);
                        if (result != null)
                        {
                            var success = controller.AddServerBySSURL(result.Text);
                            QRCodeSplashForm splash = new QRCodeSplashForm();
                            if (success)
                            {
                                splash.FormClosed += splash_FormClosed;
                            }
                            else if (result.Text.StartsWith("http://") || result.Text.StartsWith("https://"))
                            {
                                _urlToOpen = result.Text;
                                splash.FormClosed += OpenUrlFromQrCode;
                            }
                            else
                            {
                                MessageBox.Show(I18N.GetString("Failed to decode QRCode"));
                                return;
                            }
                            double minX = Int32.MaxValue, minY = Int32.MaxValue, maxX = 0, maxY = 0;
                            foreach (ResultPoint point in result.ResultPoints)
                            {
                                minX = Math.Min(minX, point.X);
                                minY = Math.Min(minY, point.Y);
                                maxX = Math.Max(maxX, point.X);
                                maxY = Math.Max(maxY, point.Y);
                            }
                            minX /= imageScale;
                            minY /= imageScale;
                            maxX /= imageScale;
                            maxY /= imageScale;
                            // make it 20% larger
                            double margin = (maxX - minX) * 0.20f;
                            minX += -margin + marginLeft;
                            maxX += margin + marginLeft;
                            minY += -margin + marginTop;
                            maxY += margin + marginTop;
                            splash.Location = new Point(screen.Bounds.X, screen.Bounds.Y);
                            // we need a panel because a window has a minimal size
                            // TODO: test on high DPI
                            splash.TargetRect = new Rectangle((int) minX + screen.Bounds.X, (int) minY + screen.Bounds.Y,
                                (int) maxX - (int) minX, (int) maxY - (int) minY);
                            splash.Size = new Size(fullImage.Width, fullImage.Height);
                            splash.Show();
                            return;
                        }
                    }
                }
            }
            MessageBox.Show(I18N.GetString("No QRCode found. Try to zoom in or move it to the center of the screen."));
        }

        private void ImportURLItem_Click(object sender, EventArgs e)
        {
            var success = controller.AddServerBySSURL(Clipboard.GetText(TextDataFormat.Text));
            if (success)
            {
                ShowConfigForm();
            }
        }

        private void splash_FormClosed(object sender, FormClosedEventArgs e)
        {
            ShowConfigForm();
        }

        private void OpenUrlFromQrCode(object sender, FormClosedEventArgs e)
        {
            Process.Start(_urlToOpen);
        }

        private void AutoStartupItem_Click(object sender, EventArgs e)
        {
            _autoStartupItem.Checked = !_autoStartupItem.Checked;
            if (!AutoStartup.Set(_autoStartupItem.Checked))
            {
                MessageBox.Show(I18N.GetString("Failed to update registry"));
            }
        }

        private void LocalPACItem_Click(object sender, EventArgs e)
        {
            if (!_localPacItem.Checked)
            {
                _localPacItem.Checked = true;
                _onlinePacItem.Checked = false;
                controller.UseOnlinePAC(false);
                UpdatePacItemsEnabledStatus();
            }
        }

        private void OnlinePACItem_Click(object sender, EventArgs e)
        {
            if (!_onlinePacItem.Checked)
            {
                if (controller.GetConfigurationCopy().pacUrl.IsNullOrEmpty())
                {
                    UpdateOnlinePACURLItem_Click(sender, e);
                }
                if (!controller.GetConfigurationCopy().pacUrl.IsNullOrEmpty())
                {
                    _localPacItem.Checked = false;
                    _onlinePacItem.Checked = true;
                    controller.UseOnlinePAC(true);
                }
                UpdatePacItemsEnabledStatus();
            }
        }

        private void UpdateOnlinePACURLItem_Click(object sender, EventArgs e)
        {
            string origPacUrl = controller.GetConfigurationCopy().pacUrl;
            string pacUrl = Microsoft.VisualBasic.Interaction.InputBox(
                I18N.GetString("Please input PAC Url"),
                I18N.GetString("Edit Online PAC URL"),
                origPacUrl);
            if (!pacUrl.IsNullOrEmpty() && pacUrl != origPacUrl)
            {
                controller.SavePACUrl(pacUrl);
            }
        }

        private void SecureLocalPacUrlToggleItem_Click(object sender, EventArgs e)
        {
            Configuration configuration = controller.GetConfigurationCopy();
            controller.ToggleSecureLocalPac(!configuration.secureLocalPac);
        }

        private void CopyLocalPacUrlItem_Click(object sender, EventArgs e)
        {
            controller.CopyPacUrl();
        }

        private void UpdatePacItemsEnabledStatus()
        {
            if (this._localPacItem.Checked)
            {
                this._editLocalPacItem.Enabled = true;
                this._updateFromGfwListItem.Enabled = true;
                this._editGfwUserRuleItem.Enabled = true;
                this._editOnlinePacItem.Enabled = false;
            }
            else
            {
                this._editLocalPacItem.Enabled = false;
                this._updateFromGfwListItem.Enabled = false;
                this._editGfwUserRuleItem.Enabled = false;
                this._editOnlinePacItem.Enabled = true;
            }
        }


        private void UpdateUpdateMenu()
        {
            Configuration configuration = controller.GetConfigurationCopy();
            _autoCheckUpdatesToggleItem.Checked = configuration.autoCheckUpdate;
            _checkPreReleaseToggleItem.Checked = configuration.checkPreRelease;
        }

        private void autoCheckUpdatesToggleItem_Click(object sender, EventArgs e)
        {
            Configuration configuration = controller.GetConfigurationCopy();
            controller.ToggleCheckingUpdate(!configuration.autoCheckUpdate);
            UpdateUpdateMenu();
        }

        private void checkPreReleaseToggleItem_Click(object sender, EventArgs e)
        {
            Configuration configuration = controller.GetConfigurationCopy();
            controller.ToggleCheckingPreRelease(!configuration.checkPreRelease);
            UpdateUpdateMenu();
        }

        private void checkUpdatesItem_Click(object sender, EventArgs e)
        {
            Task.Factory.StartNew(async () => { await updateChecker.CheckUpdate(controller.GetConfigurationCopy()); });
        }

        private void hotKeyItem_Click(object sender, EventArgs e)
        {
            ShowHotKeySettingsForm();
        }

        private void ShowLogItem_Click(object sender, EventArgs e)
        {
            ShowLogForm();
        }

        public void ShowLogForm_HotKey()
        {
            ShowLogForm();
        }
    }
}