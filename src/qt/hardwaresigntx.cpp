#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/hardwaresigntx.h>
#include <qt/waitmessagebox.h>
#include <qt/hardwarekeystoredialog.h>
#include <qt/walletmodel.h>
#include <qt/runebasehwitool.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>

#include <QFile>

HardwareSignTx::HardwareSignTx(QWidget *_widget) : QObject(_widget)
{
    tool = new RunebaseHwiTool(this);
    widget = _widget;
}

HardwareSignTx::~HardwareSignTx()
{}

void HardwareSignTx::setModel(WalletModel *_model)
{
    model = _model;
    tool->setModel(_model);
}

bool HardwareSignTx::askDevice(bool stake, QString* pFingerprint)
{
    // Check if the HWI tool exist
    QString hwiToolPath = GUIUtil::getHwiToolPath();
    if(!QFile::exists(hwiToolPath))
    {
        QMessageBox msgBox;
        msgBox.setWindowTitle(tr("HWI tool not found"));
        msgBox.setTextFormat(Qt::RichText);
        msgBox.setText(tr("HWI tool not found at path \"%1\".<br>Please download it from %2 and add the path to the settings.").arg(hwiToolPath, RUNEBASE_HWI_TOOL));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.exec();
        return false;
    }

    // Ask for ledger
    QString fingerprint = model ? model->getFingerprint(stake) : "";
    QString title = tr("Connect Ledger");
    QString message = tr("Please insert your Ledger (%1). Verify the cable is connected and that no other application is using it.\n\nTry to connect again?");
    if(HardwareKeystoreDialog::AskDevice(fingerprint, title, message.arg(fingerprint), stake))
    {
        if(pFingerprint) *pFingerprint = fingerprint;
        if(model) model->setFingerprint(fingerprint, stake);
        return true;
    }

    if(model) model->setFingerprint("", stake);
    return false;
}

bool HardwareSignTx::sign()
{
    if(askDevice())
    {
        // Sign transaction with hardware
        WaitMessageBox dlg(tr("Ledger Status"), tr("Confirm Transaction on your Ledger device..."), [this]() {
            QString fingerprint = model->getFingerprint();
            QString tmpPsbt = psbt;
            hexTx = "";
            complete = false;
            bool ret = tool->signDelegate(fingerprint, tmpPsbt);
            if(ret) ret &= tool->signTx(fingerprint, tmpPsbt);
            if(ret) ret &= tool->finalizePsbt(tmpPsbt, hexTx, complete);
        }, widget);

        dlg.exec();

        if(!complete)
        {
            QMessageBox::warning(widget, tr("Sign failed"), tr("The transaction has no a complete set of signatures."));
        }
    }

    return complete;
}

bool HardwareSignTx::send(QVariantMap &result)
{
    if(tool->sendRawTransaction(hexTx, result))
    {
        return true;
    }
    else
    {
        // Display error message
        QString errorMessage = tool->errorMessage();
        if(errorMessage.isEmpty()) errorMessage = tr("Unknown transaction error");
        QMessageBox::warning(widget, tr("Broadcast transaction"), errorMessage);
    }

    return false;
}

bool HardwareSignTx::displayAddress()
{
    if(askDevice())
    {
        // Show address on hardware
        WaitMessageBox dlg(tr("Ledger Status"), tr("Confirm Address on your Ledger device:\n%1").arg(address), [this]() {
            QString fingerprint = model->getFingerprint();
            QString tmpDesc;
            QString tmpAddress;
            complete = false;
            bool ret = tool->getAddressDesc(address, tmpDesc);
            if(ret) ret &= tool->displayAddress(fingerprint, tmpDesc, tmpAddress);
            if(ret) complete = address == tmpAddress;
        }, widget);

        dlg.exec();
    }
    return complete;
}

bool HardwareSignTx::signMessage(const QString &message, const QString &path, QString &signature)
{
    if(askDevice())
    {
        // Sign message on hardware
        WaitMessageBox dlg(tr("Ledger Status"), tr("Confirm Message on your Ledger device..."), [this, message, path, &signature]() {
            QString fingerprint = model->getFingerprint();
            complete = tool->signMessage(fingerprint, message, path, signature);
        }, widget);

        dlg.exec();
    }
    return complete;
}

void HardwareSignTx::setPsbt(const QString &_psbt)
{
    psbt = _psbt;
    hexTx = "";
    complete = false;
}

void HardwareSignTx::setAddress(const QString &value)
{
    address = value;
}

bool HardwareSignTx::process(QWidget *widget, WalletModel *model, const QString &psbt, QVariantMap &result, bool send)
{
    // Sign transaction
    HardwareSignTx tool(widget);
    tool.setModel(model);
    tool.setPsbt(psbt);
    bool ret = tool.sign();

    if(send)
    {
        // Send transaction
        QVariantMap resultTool;
        if(ret) ret &= tool.send(resultTool);

        // Process result
        if(ret)
        {
            result["txid"] = resultTool["txid"];
            if(resultTool.contains("contracts"))
            {
                QList<QVariant> contracts = resultTool["contracts"].toList();
                for(QVariant contract : contracts)
                {
                    result["address"] = contract.toMap()["address"];
                    break;
                }
            }
        }
    }
    else
    {
        // Process result
        if(ret)
        {
            result["hextx"] = tool.hexTx;
        }
    }

    return ret;
}

bool HardwareSignTx::display(QWidget *widget, WalletModel *model, const QString &address)
{
    // Display address
    HardwareSignTx tool(widget);
    tool.setModel(model);
    tool.setAddress(address);
    return tool.displayAddress();
}


bool HardwareSignTx::sign_message(QWidget *widget, WalletModel *model, const QString &message, const QString &path, QString &signature)
{
    // Display address
    HardwareSignTx tool(widget);
    tool.setModel(model);
    return tool.signMessage(message, path, signature);
}

