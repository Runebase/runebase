#ifndef RUNEBASEPUSHBUTTON_H
#define RUNEBASEPUSHBUTTON_H
#include <QPushButton>
#include <QStyleOptionButton>
#include <QIcon>

class RunebasePushButton : public QPushButton
{
public:
    explicit RunebasePushButton(QWidget * parent = Q_NULLPTR);
    explicit RunebasePushButton(const QString &text, QWidget *parent = Q_NULLPTR);

protected:
    void paintEvent(QPaintEvent *) Q_DECL_OVERRIDE;

private:
    void updateIcon(QStyleOptionButton &pushbutton);

private:
    bool m_iconCached;
    QIcon m_downIcon;
};

#endif // RUNEBASEPUSHBUTTON_H
