import base64
import json
import os
import pprint
from hashlib import md5

from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad


class Encryptor:
    secret_code = 'x0i2O7WRiANTqPmZ'.encode("utf-8")

    def decrypt(self, data: str) -> str:
        encrypted = base64.b64decode(data)
        assert encrypted.startswith(b"Salted__")
        salt = encrypted[8:16]
        key_iv = self._get_key_iv(self.secret_code, salt)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return unpad(aes.decrypt(encrypted[16:]), AES.block_size).decode()

    def encrypt(self, data: str) -> str:
        salt = os.urandom(8)
        key_iv = self._get_key_iv(self.secret_code, salt)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = aes.encrypt(padded_data)
        encrypted_data = b"Salted__" + salt + encrypted_data
        return base64.b64encode(encrypted_data).decode()

    def _get_key_iv(self, data,  salt, output=48):
        assert len(salt) == 8, len(salt)
        data += salt
        key = md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output]



enc = Encryptor()
dec = enc.decrypt("U2FsdGVkX19A6qN3F+0o6lOTabgd1kGLeXza/0qTu4QR8d2A/wUUXyA+GoVrq8tqC0UXTLxxvSmMGUiMmXds6Ylp82jSTW6f1DwUV9Bj2Td36dDU9hQNjaZDasawBg7O1SpABu2O1v37r3jB4xKMy0VfShCgH1/Jtj3fQr8G1+w1a3lMf2WQaiQMNKe0zCCfaHzCVZUk8EvTIfklcGgijMSF69eq3GIxAjoUPDNCNNItQgJjacquKFrpCsjo9KpfBr+4e1B8SENAarLE/AFfZK2IkZAgYyr8IsFRF6wjocYnITglIpbO1uOLy+AKTbbbdNZT7TEDZeRBCWD7TOYaP8gUG/1zq5otXLVwW1ovPg92SeH/f2us9iS05TD1nxA6NKjNn1K9ez7RSAKPHS8gGXI1WyCwQI1D4/yifqnggPlYtBMSpTvPPn3ZL5VFGc6Edz1zjFdUGI9MF1uMmwgGxGgEZSS2AMIQWCymsmqMcGfPziZLsmCvMYEKLk0O6zEf8nY6X9N2xDabpwi2xXgzroHb0Dg9gPfA+oDQyfSS71o0QxYhbUnylmXllwTgjDZkb/BWzHW+Lu8v6kz3vOZaxAwCBl+fkNuI0Lka+CTN0m3CKBw5zdBRGLNX7Tp/hqOj2LqNf5IktpbUzYiMtc9p90lorH+aAtsdH5tDlhcpv35iZnoVRhDRSeiAlHq6WwZzai9kz0BOKZlXgISFng2kvmsDAW3CpF8ipb7V+VU4OeHzqRSJFmLiTfV7FN0Q73gSa3l64vmgGAESXHf8aDWys+t5fHbesd0/N4cS5dGlAn7lY4tLw3PSijvaZm7mlaC+BJ3uOL1ykJ9j6MhBzCFo9ERB/QB6cRvVzY35XOiGN8IZe+siYmO1kL/E5QCuiPx4VFpyH5RWzy0d+lOC23aP4QnPOEQA1g09WFIAMbtNmHvMOG2bTfdvRF4dE8J69xpvX7IbGUlFt6PA+pYGpf0l6cLvpSc2rhS4aNB4FzgeYY1rE/khNVjw0fJQ2mV+1JjW8ErQGkizfN7oYRwQGGseJKtmSJD6vVY34BGtMrpZEhJfHKjaLbWvXT3LSTrJJv4k251so0I4saj0haN++mJpZ1BtIZ3G+NzLe9c0xqg/Q9S28wG4y514ag/Y9UrBQQMvDmvE5xhpBgVeAaq4QRQ2yZIxtDcPc6q4qve0RUrjHCE/tfdnh76CsrreEIgDHKSPqtKvWqDymUFXW+DowBtc19dqenmV+kZA7EZTzj1XLC4pw6BpRTWopNj2F0EpsTDYBt1VbVvn7zXR1Zx7iBfmVNvY8I2rqbKqLqHV2QWBSddi+6rPR63tj/l4GJSthvTlgjQtuveTTCI102CYDCvKiyzm/xurpQYHcSioMMyhr00HmJEe6WdhklYD+gTANQFpKJ4dZ432AzSY/8FMzTNYduxCrc0o8NhYqOsJd4KR5XlnNanG2ZaOLusBuYN54hwnC7/q3Noblk/CHWXIVFMrY6+6rPdYnK8kIibOueKCOUv2KK2DjB6aYFWvYLvvCxXDTH007FoU5UArcn/eXQUoG/yaEYKNcDaoz6NyIAFl5OP3yjoTeFLh7lapiWGAEOSwDGgDVkffAEzINAu1sJTYKQD26y1SZl1iIGhW5y0RjP2/6oFem3di+ArYlWK6oCbBHzvyZ97Ye2JIBmg8+ABM0zErcW47r0En6eU39TYkbWfh9r20TSCHkON0QjUrR4LtunrdfDdrSztuE0gM42/6p8vEWse+npXqQ7q+HImp89o9dl5LmDRPl/ZwLMSQfVzLOEsHSBMJnfFppw8SEBetuFQkkphkxjby6a175xiNs2TAh+HYJFdS+Z6mwLaTzrylKCYnOk/9L+W8emgeZ/pxJnUTNR260ufuQvW6sbNgMYCvHLNuySPGT7gQIEuP16lOFLBUlVs5HAJNhX4bVmYV5phqbKodTgX9oncHL85Cxtix6SxK4LbkDlxpWlFybdFgomrut6EpX3a3F1MtxvYwLAk5rt69bncm8sFhj1s4Oj9kJJfg26LRX55slTrYtpGR00PCKLGmexXWISjpzBuj7LlCQycUs9sc4x9ZTHt0VYn5m4z9zCyuxYAhMIyRhbSG6W1S5mSoBPPoViF11VUMrl3vXuZQBfGUJ0IOwMAQ+WO0u16fMPWtVnzl2QdBHQaes2yOxMxnGRe50N2QuUnIRqjrphBMs9JTLVyCmdA0W4/wOXXu247WhpTUoY5xsnYvjwUzVCs7Oce3P+3lNib2+/pCseGWJ38uv5wYdBgEjWWjP+2lKk3ypVbQ8skwmeJVoj+P8dp8uL8ULs5/JD+SjC1EgqQl05wvqrCxW6R10dsLW5pd65QkG0KMDT89nwK+iK0sCkSruUW8GS2VlvYnQFi1sIFwbDb1h8UUr+gcnzLSQKt8kdKtCZyDE6oIrU1hZEEfyP1+eeVBfwc6ZJ5mwcGcSVgqI7JBmrJY5vCzwEHfAZ6nfxqTBs5nALBeDwCbzd6R/4Kqz50P05JMR4qSjB0dDS4llFyJQaxCyGVJfChTHjXhj17nMDDGy8eX/cOKYYs12XJ6oM1Kq2gBC8jScJ9Kg7OK2ohSRMGHpQyPgYAs0Sj+WPb3+E2jQuw+Bel3so30SL8XM44SizxWnvTsPX/q7dWWA3yti6KJf1YlooR02robvlgi+tGqJkI0rh8ruXNr5N7uHXGqlt8tronG0ko6bVH8pW2dCvyIxMT85Vg/RplL/LHmNENdSMnubLxle/PGDAKbI06GKsqbPs9aGFebebTNiCoAzILaoGJgUyegf06+XrGjiPC4vY6IEiEfx17AKzyhnK8hsTAJYj2ZMjHcS+96qgiBlP+l3l6ELsz6QE3XgoOL2YSSdYCMR2T2F/hUPo29qEMPakK+vgXwGmsKRw28A5AvReZDMBpTB02TASTP7a/1/Pv4nN65n+h3DFWt1z3p4X0siw4baUcEzBlEOIsoVhPqkftbzmA5UTI6F8p6MJurU/BVmzZg3g3TUf66Evvdx8WebMk2MDmd+oi6KpMeZ2xB1OHRTK1aJ3PaxwhTFB95RXxojv/zr1wa507+ZUYxzbI47DYF6ye1+lxDGG92BwAM9+A2tjTNHW0RGJam79K6gKIJFWVhX/QS/eXF6KN2SlAcwmKUJqNTr+CkJu09sBRVaiUNJzYLl1xI3xu3uCL6LrC5X6XuGIoRnSafQDrGOIwFFg1UUPUxRQzyW5O8x71KyM06Xf4MoBolgyUyz+INxGepPq8tVcwCc/FQvenEkKaEKrqs0ryXQg==")
jsonDec = json.loads(dec)
jsonDec['party'][0]['level'] = 1000
jsonDec['party'][0]['boss'] = True

pprint.pprint(jsonDec)
print(enc.encrypt(json.dumps(jsonDec)))
