#include "NitroKey.h"

#include "crypto/CryptoHash.h"

#include <string>
#include <vector>
#include <memory.h>
#include <NitrokeyManager.h>
//#include <CommandFailedException.h>
//#include <LibraryException.h>
//#include <DeviceCommunicationExceptions.h>

NitroKey::NitroKey()
{
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    manager->set_loglevel(9);
    if(not manager->is_connected())
    {
        manager->connect();
    }
}

bool NitroKey::isValid() const
{
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    return manager->is_connected();
}

bool NitroKey::isUnlocked() const
{
    return unlocked;
}

NitroKey::Status NitroKey::unlock(const QString& pin)
{
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    unlocked = false;
    Status status = Status::ERROR;
    //try {
        QByteArray chars = pin.toLatin1();
        manager->enable_password_safe(chars.constData());
        status = Status::OK;
        unlocked = true;
    /*}
    catch (CommandFailedException &e) {
        if(e.reason_wrong_password()) {
            status = Status::WRONG_PASSWORD;
        }
        if(e.reason_AES_not_initialized()) {
            status = Status::AES_NOT_INITIALIZED;
        }
        if(e.reason_not_authorized()) {
            status = Status::NOT_AUTHORIZED;
        }
    }
    catch (DeviceCommunicationException &e) {
        status = Status::ERROR;
    }
    catch (LibraryException &e) {
        status = Status::ERROR;
    }*/
    return status;
}

NitroKey::Status NitroKey::lock()
{
    unlocked = false;
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    Status status = Status::ERROR;
    //try {
        manager->lock_device();
        status = Status::OK;
    /*}
    catch (CommandFailedException & e) {
        status = Status::ERROR;
    }
    catch (DeviceCommunicationException &e) {
        status = Status::ERROR;
    }
    catch (LibraryException &e) {
        status = Status::ERROR;
    }*/
    return status;
}

QByteArray NitroKey::rawKey() const
{
    return m_key;
}

QMap<QVariant, QString> NitroKey::loadKeys() const
{
    QMap<QVariant, QString> map;
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    std::vector<uint8_t> s = manager->get_password_safe_slot_status();
    for(int slot = 0; slot < s.size(); slot++)
    {
        if(s[slot])
        {
            const char* name = manager->get_password_safe_slot_name(slot);
            QVariant k(slot);
            QString v(name);
            map.insert(k, v);
        }
    }
    return map;
}

void NitroKey::setPassword(QVariant slot)
{
    int s = slot.toInt();
    std::shared_ptr<nitrokey::NitrokeyManager> manager = nitrokey::NitrokeyManager::instance();
    auto passwordCstr = manager->get_password_safe_slot_password(s);
    QString password = QString::fromStdString(passwordCstr);
    m_key = CryptoHash::hash(password.toUtf8(), CryptoHash::Sha256);
}

NitroKey *NitroKey::clone() const
{
    return new NitroKey(*this);
}
