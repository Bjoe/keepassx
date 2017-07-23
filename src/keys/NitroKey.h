/*
*  Copyright (C) 2017 Joerg-Christian Boehme <joerg@chaosdorf.de>
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 2 or (at your option)
*  version 3 of the License.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef KEEPASSX_NITROKEY_H
#define KEEPASSX_NITROKEY_H

#include <QByteArray>
#include <QString>
#include <QVariant>
#include <QMap>
#include "keys/Key.h"

class NitroKey : public Key
{
public:
    enum class Status : int {
        OK,
        WRONG_PASSWORD,
        AES_NOT_INITIALIZED,
        NOT_AUTHORIZED,
        ERROR
    };

    NitroKey();
    bool isValid() const;
    bool isUnlocked() const;
    Status unlock(const QString &pin);
    Status lock();
    QByteArray rawKey() const;
    QMap<QVariant, QString> loadKeys() const;
    void setPassword(QVariant slot);
    NitroKey *clone() const;

private:
    QByteArray m_key;
    bool unlocked = false;
};

#endif // NITROKEY_H
